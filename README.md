# SubscriptionWatch

独立部署的订阅访问风控系统。

- [风控后台 v3.7.0](SubscriptionWatch/README.md)：Docker部署，订阅记录、7条风险规则、风险预览、Telegram通知、IP数据库管理。
- [Xboard采集插件 v3.7.0](SubscriptionWatchCollector/README.md)：轻量采集与签名账号控制。
- [安装和升级](SubscriptionWatch/UPGRADE.md)
- [数据备份与恢复](SubscriptionWatch/BACKUP.md)

## 部署后台

公开仓库，任何人均可下载，无需 GitHub 账号或 SSH 密钥。在 Ubuntu 风控 VPS 上以 root 执行，需预先安装 Git、Docker 和 Docker Compose 插件。

### 一键部署

下载项目、构建镜像并启动（目标目录必须尚不存在）：

```bash
git clone https://github.com/kele812/SubscriptionWatch.git /opt/SubscriptionWatch-repo && bash /opt/SubscriptionWatch-repo/deploy.sh
```

### 一键更新

下载最新版、备份已有数据并重建服务：

```bash
bash /opt/SubscriptionWatch-repo/update.sh
```

宝塔 HTTPS 网站反向代理到 `http://127.0.0.1:18080`。更新继续使用原数据卷和账号；备份保存在 `/opt/SubscriptionWatch-backup-*`，需要自行管理磁盘空间。Xboard 插件需单独更新。

旧 SSH 下载方式迁移、部署说明见 [一键部署与更新文档](DEPLOY.md)。首次登录和插件接入步骤见 [后台说明](SubscriptionWatch/README.md)。

仓库只保存源码和公开测试夹具，不保存真实账号凭据、运行数据库或备份。

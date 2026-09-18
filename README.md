# SubscriptionWatch

独立部署的订阅访问风控系统。

- [风控后台 v3.7.0](SubscriptionWatch/README.md)：Docker部署，订阅记录、7条风险规则、风险预览、Telegram通知、IP数据库管理。
- [Xboard采集插件 v3.5.0](SubscriptionWatchCollector/README.md)：轻量采集与签名账号控制。
- [安装和升级](SubscriptionWatch/UPGRADE.md)
- [数据备份与恢复](SubscriptionWatch/BACKUP.md)

## 部署后台

在有仓库读取权限的VPS拉取本仓库后，进入 SubscriptionWatch 子目录执行 docker compose up -d --build。详细HTTPS反代、首次登录和插件接入步骤见后台README。

仓库只保存源码和公开测试夹具，不保存真实账号凭据、运行数据库或备份。

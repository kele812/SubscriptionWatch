# SubscriptionWatch v3.9.5

## 上传插件

后台和采集插件统一为 **v3.9.5**。下载 [后台 ZIP](https://github.com/kele812/SubscriptionWatch/raw/refs/heads/main/downloads/SubscriptionWatch-v3.9.5.zip) 和 [采集插件 ZIP](https://github.com/kele812/SubscriptionWatch/raw/refs/heads/main/downloads/SubscriptionWatchCollector-v3.9.5.zip)。先更新风控后台，再在 Xboard 插件管理上传新版插件并启用。

本版减少登录和切换页面时的串行请求等待。若后台仍慢，容器日志会记录超过 1 秒的接口类别与处理耗时，便于区分服务端查询和外部网络延迟。

先在风控后台添加面板，再把风控 HTTPS 地址、面板标识和采集密钥填入插件。可信代理 IP 只填写你实际使用的反代 IP；Xboard 原有的每分钟计划任务需正常运行。

要区分客户来源 IP 与经过的反代，在每台反代的 Nginx `location /` 内覆盖这两个请求头，并填写该反代自己的公网 IP 和名称：

```nginx
proxy_set_header X-Watch-Proxy-IP "反代公网IP";
proxy_set_header X-Watch-Proxy-Name "自定义反代名称";
```

插件只在该 IP 确实出现在本次请求的可信转发链中时记录反代名称。直连或链路未核对成功时显示“未记录外部反代”；升级前的历史反代标识显示“未核实”。反代 IP 和名称由各台反代自行填写，不在程序中固定。

## 一键部署

在 Ubuntu 风控 VPS 上以 root 执行，先安装 Git、Docker 和 Docker Compose。下面命令下载代码、构建并启动服务，目标目录需尚不存在：

```bash
git clone https://github.com/kele812/SubscriptionWatch.git /opt/SubscriptionWatch-repo && bash /opt/SubscriptionWatch-repo/deploy.sh
```

## 一键更新

下载最新版、备份数据并重启风控后台：

```bash
bash /opt/SubscriptionWatch-repo/update.sh
```

原账号和数据保留，备份在 `/opt/SubscriptionWatch-backup-*`。采集插件需在 Xboard 单独上传更新。如果旧安装使用 SSH 下载，先执行：

```bash
git -C /opt/SubscriptionWatch-repo remote set-url origin https://github.com/kele812/SubscriptionWatch.git
```

## 宝塔反代

1. 将域名解析到风控 VPS，在宝塔添加此域名的网站。
2. 为网站申请 SSL，启用 HTTPS。
3. 添加反向代理，目标地址填 `http://127.0.0.1:18080`，关闭代理缓存。
4. 浏览器打开 `https://你的域名`，首次访问创建账号密码，再添加 Xboard 面板并配置插件。

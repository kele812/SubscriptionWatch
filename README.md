# SubscriptionWatch v4.0.9

## 上传插件

后台和采集插件统一为 **v4.0.9**。下载 [后台 ZIP](https://github.com/kele812/SubscriptionWatch/raw/refs/heads/main/downloads/SubscriptionWatch-v4.0.9.zip) 和 [采集插件 ZIP](https://github.com/kele812/SubscriptionWatch/raw/refs/heads/main/downloads/SubscriptionWatchCollector-v4.0.9.zip)。先更新风控后台，再在 Xboard 插件管理上传新版插件并启用。访问记录同时展示“结果”（这次请求）和“当前状态”（该用户现在是否可疑、是否达到24小时请求上限，以及已计入次数和下一次序号）；当前状态还会显示其中通过 IP／域名白名单放行的次数，升级前的旧记录标为未分类。可在该行单独重置用户24小时计数，访问历史和可疑标记保留。

风险规则有独立菜单。可按面板开启“仅允许中国大陆或白名单 IP 获取订阅”；白名单支持 IP、域名和备注，域名解析失败时不匹配。用户白名单或 IP／域名白名单命中后，跳过所有订阅风控规则，包括每日次数和已有可疑标记；访问仍记录。未命中白名单的大陆来源仍按其他规则检查。非指定客户端只拦截本次订阅，不标记可疑；多个中国大陆或非中国大陆 IP 在达到阈值的当次标记并跳转；云服务器 IP 每次请求都跳转，60 分钟第 3 次或 720 分钟第 10 次标记可疑。黑名单命中可选择启用拦截。每个用户滚动 24 小时默认最多请求 30 次，第 31 次起跳转，成功和拦截都计数；上限本身不标记可疑。手动取消可疑标记后，该用户每日次数从零重新计算，旧访问记录保留。风控后台失联或审核超时时，插件拒绝本次订阅，白名单也不例外。

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

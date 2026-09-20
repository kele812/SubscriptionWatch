# 代理访问采集节点 · 3.8.0

这是 XboardNode-Plus 的配套节点构建，**安装在代理节点服务器**，不是安装到 Xboard 面板。风控后台更新后，原有订阅监测继续工作；只有更换节点程序并配置接入的节点才会上报目标地址。

## 部署

1. 更新风控后台，在“代理访问记录”→“添加采集节点”生成该节点的 `watch_access` 配置。风控后台必须通过有效证书的 HTTPS 访问。
2. 在有 Docker 的构建机器下载本仓库并构建（首次编译较慢；建议至少4GB可用内存，勿在忙碌的Xboard面板机上编译）：

   ```bash
   git clone https://github.com/kele812/SubscriptionWatch.git
   cd SubscriptionWatch
   docker build -f node-access/Dockerfile -t subscriptionwatch-node:3.8.0 .
   ```

3. 保存旧节点程序、镜像名称和配置。在当前节点 `config.yml` **顶层**加入后台生成的三项：

   ```yaml
   watch_access:
     url: "https://你的风控域名"
     node: "后台生成的节点标识"
     secret: "后台生成的独立密钥"
   ```

4. Docker部署的节点：在原Compose中将节点镜像改为 `subscriptionwatch-node:3.8.0`，保留原有网络模式、端口、证书挂载和配置挂载，再重建该节点容器。需要将配置挂载到 `/etc/XboardNode-Plus/config.yml`。其他机器构建的镜像可通过 `docker save` / `docker load` 转移。
5. 二进制部署的节点：可从镜像取出程序，备份旧程序后替换原来的可执行文件，保留原服务和启动参数。取出命令：

   ```bash
   docker create --name watch-node-export subscriptionwatch-node:3.8.0
   docker cp watch-node-export:/usr/local/bin/xboard-node ./xboard-node-watch-3.8.0
   docker rm watch-node-export
   chmod +x ./xboard-node-watch-3.8.0
   ```

6. 重启会中断该节点的现有连接，先选择一个测试节点。出现兼容问题时恢复旧镜像/程序和配置。
7. 在风控后台输入已采集用户的 ID 和对应邮箱，点击“开启采集”，等待约30秒后通过此节点新建连接。在后台查看目标域名/IP、端口、协议、来源IP及时间。第一次开启前的连接不补采。

同一进程管理多个节点时，顶层配置会被各实例继承，后台节点名称代表这一组；需要逐节点区分时用独立配置/进程和独立接入密钥。使用原先仅环境变量配置的部署时，请改用配置文件加入此功能。

## 保存与负载

- 默认仅指定用户，最多同时100名/面板。原始记录在风控机保存3天，按分钟分批清理，过期记录立即不再展示；不写入Xboard数据库。
- 每个节点内存队列最多1000条，批次100条，每10秒上传；失败最多重试3次。过载、重启或网络故障可能丢失记录，界面显示队列/丢弃/失败数量；这些计数在节点进程重启后归零。该功能不是完整审计日志。
- 每30秒同步指定用户。策略超过90秒未更新时停止采集。停止用户后风控机立即拒收，新策略生效后节点停止新增。
- 每条记录表示内核观察到的连接目标，不能证明网页打开成功，也不是HTTP请求次数。复用连接、UDP会话、后台应用会影响记录粒度；不保证能得到域名，不包含HTTPS路径、页面内容或原始UA。
- 启用 `watch_access` 时，目标地址只报给风控机，取消原节点向Xboard发送的访问诊断内容；正常用户同步、流量计费、在线状态仍按原配置上报。
- 风控机磁盘可用空间不足512MB时拒收此类记录，优先保护主服务。节点不得填写管理员Cookie、Xboard API Token或订阅采集密钥。

基于上游 [XboardNode-Plus](https://github.com/xboardnext999/XboardNode-Plus/tree/f2aca7940600207cc75ab4fe0c91003b6bd6dfeb) 固定提交构建，覆盖层只改动采集接入部分。

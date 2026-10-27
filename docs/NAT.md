# NAT 端口映射

0.52.0 增加 UPnP SSDP 发现；0.51.0 增加 PCP/UPnP 续租循环；0.50.0 增加 NAT-PMP 续租循环；0.42.0 增加 NAT-PMP（RFC 6886）UDP 端口映射客户端；0.43.0 增加 PCP（RFC 6887）MAP 客户端；0.44.0 增加 UPnP IGD AddPortMapping/DeletePortMapping 客户端。它们是端口映射管理工具，不是 NAT 穿透服务器、反向隧道或 WireGuard。

## CLI

```text
relay nat-map --gateway 192.168.1.1 \
  --internal-port 9000 --external-port 40000 --lifetime-secs 3600
relay nat-map --gateway 192.168.1.1:5351 --internal-port 9000 --delete
relay nat-map --gateway 192.168.1.1 --internal-port 9000 --lifetime-secs 3600 --renew
relay nat-map --gateway 192.168.1.1 --internal-port 9000 --lifetime-secs 120 --renew --renew-after-secs 30
relay pcp-map --gateway 192.168.1.1 --internal-port 9000 --lifetime-secs 120 --renew
relay upnp-discover --timeout-secs 3
relay upnp-subscribe --description-url http://192.168.1.1:5000/rootDesc.xml --callback http://192.0.2.10:9000/events --timeout-secs 1800
relay upnp-unsubscribe --event-url http://192.168.1.1:5000/events --sid uuid:...
relay upnp-events --description-url http://192.168.1.1:5000/rootDesc.xml --callback http://192.0.2.10:9000/events --timeout-secs 1800
relay nat-map --gateway 192.168.1.1 --internal-port 9000 --renew --retry-secs 5 --retry-max-secs 60 --state-file /var/lib/relay/mapping.json
relay upnp-map --description-url http://192.168.1.1:5000/rootDesc.xml --internal-port 9000 --external-port 40000 --lifetime-secs 600 --renew
```

- Gateway 接受 `IP` 或 `IP:PORT`；省略端口用 5351；只支持 IPv4。
- 请求/响应使用 NAT-PMP 12/16 字节 UDP 报文：版本 0、UDP map opcode 1、内部端口、建议外部端口、生命周期。
- 成功返回 `gateway/internal_port/external_port/lifetime_secs/epoch` JSON；网关拒绝、超时、版本/长度错误明确失败。
- `--external-port 0` 表示由网关分配；`--delete` 发送生命周期 0。
- 生命周期上限 7 天；内部端口不能为 0。

## PCP

```text
relay pcp-map --gateway 192.168.1.1 \
  --internal-port 9000 --external-port 0 --lifetime-secs 3600
relay pcp-map --gateway 192.168.1.1:5351 --internal-port 9000 --delete
```

- PCP 版本 2、MAP opcode 1、UDP 协议 17；60 字节请求/响应。
- 客户端随机生成 12 字节 nonce，响应必须匹配；拒绝结果码、版本、长度错误明确失败。
- 外部 IP 使用 16 字节字段，IPv4-mapped 地址会还原成 IPv4；生命周期上限 7 天。
- 与 NAT-PMP 一样只管理一个映射，不改变 Relay 数据路径。
- UPnP 事件订阅：`subscribe` 解析 description 的 `eventSubURL`，发送 `SUBSCRIBE`（CALLBACK/NT/TIMEOUT），返回 SID/事件 URL/超时；`renew` 用 SID 续订；`unsubscribe` 发送 `UNSUBSCRIBE`。
- `upnp-events` 启动本地回调 HTTP 服务、自动订阅、按半超时续订、逐条输出事件 JSON，Ctrl-C 时退订；回调必须是具体 IPv4/localhost + 端口。
- 事件 JSON 同时包含原始正文和 `properties`：从叶级属性元素提取的键值（去命名空间前缀，最多 64 项、每值 4096 字节）；不执行 XML、不解析实体，也不做事件动作分发。
- `upnp-discover` 向 `239.255.255.250:1900` 发送 SSDP M-SEARCH（IGD 设备类型），在超时内收集 `LOCATION`，按 LOCATION 去重并输出 JSON；测试使用显式单播目标，受控网络可用 `discover_at`。目前只做 IPv4，不解析设备 XML，也不自动选择网关。
- 三种客户端的 `--renew` 都可配 `--retry-secs` 和可选 `--retry-max-secs`：请求失败后从初始间隔开始、每次翻倍到上限，直到成功或 Ctrl-C；省略重试则失败即退出，零间隔或上限小于初始值拒绝。成功映射后间隔回到初始值。
- `--state-file` 在每次成功映射后原子写入最后一条映射 JSON；`--delete` 成功后删除该文件。
- `--restore-state` 配合 `--state-file`：创建新映射前，如果旧记录的内/外端口不同，先删除旧映射，再创建新映射；删除失败则中止，旧状态文件保留。它不会在普通启动时自动运行。
- CLI 原先在异步 main 内嵌套创建 Tokio runtime，实际运行 `nat-map`/`pcp-map`/`upnp-map`/反向/事件命令会 panic；0.74.0 改为直接 `await`，并加入真实子进程回归。
- NAT-PMP、PCP、UPnP 的 `--renew` 持续续租直到 Ctrl-C；间隔默认生命周期的一半，也可用 `--renew-after-secs` 指定。续租间隔必须小于生命周期；每次成功映射输出一行 JSON，失败即退出并保留错误。`--delete` 优先，不会续租。PCP 每次重新获取 nonce；UPnP 每次重新解析 description/control URL，能感知控制地址变化。

## UPnP IGD

```text
relay upnp-map --description-url http://192.168.1.1:5000/rootDesc.xml \
  --internal-client 192.168.1.10 --internal-port 9000 \
  --external-port 40000 --lifetime-secs 3600
relay upnp-map --description-url ... --internal-port 9000 --external-port 40000 --delete
```

- 不实现 SSDP 发现；调用者提供 IGD description URL。
- 从 description 中定位 `WANIPConnection`/`WANPPPConnection` 的 `controlURL`，解析相对 URL。
- 发送 SOAP `AddPortMapping` 或 `DeletePortMapping`，UDP、租约时间、启用标记和固定描述；HTTP/SOAP 错误码明确失败。
- `internal-client` 默认 `127.0.0.1`，真实使用应填内网地址；external port 必须非 0。

## 验证与限制

- 集成测试用本机假 NAT-PMP 网关验证请求字段、成功映射、epoch/外部端口解析、删除请求、拒绝响应和取消前多次续租；假 PCP 网关验证 nonce、成功映射、IPv4-mapped 外部地址、删除、拒绝和续租；假 UPnP HTTP 服务验证 description 解析、AddPortMapping/DeletePortMapping 的 control URL、SOAP 字段和续租；假 SSDP 服务验证 M-SEARCH 字段、LOCATION 解析和重复响应去重；假 HTTP 事件服务验证 SUBSCRIBE/续订/UNSUBSCRIBE 的 SID、CALLBACK 和超时；回调服务测试验证 NOTIFY 接收、SID/SEQ、属性提取和取消后退订。
- SSDP 仅收集 IGD LOCATION；UPnP 事件不解析嵌套属性语义，回调仅支持明文 IPv4/localhost；未实现完整设备/服务描述筛选、PCP 固定源端口 5351、IPv6 完整矩阵、映射状态持久化、指数退避、WireGuard、公网入口和真实家用路由器验收；固定间隔重试已实现；模块 16 仍为部分实现。
- 该命令只管理一个映射，不改变 Relay 规则或监听；需要网关实际支持 NAT-PMP。

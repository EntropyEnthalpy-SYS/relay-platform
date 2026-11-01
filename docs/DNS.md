# DNS 托管记录、健康摘除与 DDNS

0.22.0 增加 DNS 服务商、区域和托管记录；0.23.0 增加入口健康摘除。它解决“平台创建 A/AAAA/CNAME 记录并核对服务商实际状态”的运维需求；不是完整权威 DNS 池，也不会声称 DNS 已传播。

## 数据与安全边界

- 服务商、区域和记录都保存在 `metadata`（`dns_provider:<id>`、`dns_zone:<id>`、`dns_record:<id>`），因此 schema v5、恢复日志格式 4、备份和连续恢复不变。
- 服务商 API 令牌必须可逆保存才能调用外部 API。读取接口只返回 `token_set`，不返回令牌原文；只有系统管理员能读写 DNS。API 令牌即使带 `users:write` 也不能访问 `/dns/*`，只接受登录会话。
- API 基础地址必须是 HTTPS；只有回环地址允许 HTTP，供本机 mock/测试使用。地址中不允许用户名、密码、查询或片段。系统管理员能把控制器指向可达地址，因此该角色本身必须可信。
- 目前只实现 Cloudflare 兼容 API。服务商 API 返回 `success:false` 或非 2xx 时记录错误，不用本地期望值伪装成已生效。

## 区域与记录

```json
{
  "provider_id": "…",
  "name": "example.com",
  "mode": "observe",
  "min_keep": 1
}
```

`mode`：

- `observe`：读取服务商记录并报告“将创建/将更新/保留/差异”，不调用写 API，不写服务商。
- `apply`：创建、更新和删除本平台管理的记录。

记录字段：`name`（FQDN 或服务商接受的相对名）、`type`（`A`、`AAAA`、`CNAME`）、`content`、`ttl`（1..86400）、`proxied`、`enabled`。A/AAAA 内容必须是 IP，CNAME 内容必须是主机名。

可选 `health`：`{"node_id":"…","rule_id":"…"}`。填写后同步器要求该节点心跳不超过 90 秒、节点资料为活动状态，并且该规则至少有一个 `eligible=true` 且 `status=healthy` 的目标报告；否则把记录当作“暂不可用”：观察模式报告 `would-health-remove`，应用模式摘除服务商记录。心跳恢复或目标恢复后下一次同步会重建。未知、过期、无心跳和停用节点一律 fail closed。更新记录时传 `clear_health:true` 可移除该门控。

每条记录创建时带 `relay:<record id>` 注释。同步时优先按保存的服务商记录 ID 匹配；丢失时按“类型 + 名称 + relay 注释”恢复，不会接管同名但没有本平台注释的外部记录。删除本地记录时，应用模式会先删除对应服务商记录；观察模式只删除本地记录。

`min_keep` 是删除停用/健康摘除记录时的保护：只有当前有效（本地启用且通过健康门控）的托管记录数不少于该值，才删除服务商记录；否则保留并报告 `kept`。

## 同步

`POST /api/v1/dns/zones/{id}/reconcile` 执行一次显式同步，返回：

```json
{
  "zone_id": "…", "mode": "observe", "observed": 2,
  "created": 0, "updated": 1, "deleted": 0, "unchanged": 1,
  "kept": 0, "errors": 0,
  "actions": [{"record_id": "…", "action": "would-update", "detail": "A edge.example.com -> 203.0.113.12"}]
}
```

`created`/`updated`/`deleted` 在观察模式下分别表示“将创建/将更新/将删除”的数量。错误逐条写入记录的 `last_error`，成功同步会清除该错误并记录 `last_observed`。这正是“配置提交”和“外部 DNS 接受”的区分：控制器只证明服务商 API 接受了请求，不证明递归解析器、缓存或权威服务器已传播。

目前每区域只读取服务商第一页（最多 100 条）记录；分页、批量操作和并发冲突重试未实现。

## DDNS

`POST /api/v1/dns/records/{id}/ddns`，请求 `{"content":"203.0.113.31"}`：

1. 只允许 A/AAAA 记录；
2. 更新本地内容；
3. 立即执行该区域一次同步，观察模式只报告差异，应用模式写入服务商。

该接口适合外部脚本按当前公网 IP 调用。它不自动探测节点公网 IP，也不保存历史 IP；接入节点探针/DDNS 调度器是后续工作。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/api/v1/dns/providers` | 列表/创建服务商 |
| GET/PUT/DELETE | `/api/v1/dns/providers/{id}` | 读取（令牌脱敏）/更新/删除 |
| GET/POST | `/api/v1/dns/zones` | 列表/创建区域 |
| GET/PUT/DELETE | `/api/v1/dns/zones/{id}` | 读取/更新/删除；有记录时删除返回 409 |
| GET/POST | `/api/v1/dns/zones/{id}/records` | 列表/创建记录 |
| GET/PUT/DELETE | `/api/v1/dns/records/{id}` | 读取/更新/删除 |
| POST | `/api/v1/dns/zones/{id}/reconcile` | 显式观察/应用同步 |
| POST | `/api/v1/dns/records/{id}/ddns` | 更新 A/AAAA 并同步 |

所有接口仅系统管理员，审计动作包括 `dns.provider.*`、`dns.zone.*`、`dns.record.*`。面板“DNS 管理”页提供新增/编辑/删除、记录列表、立即同步和 DDNS。

## 独立权威 DNS 池（0.137.0，可选功能）

在「可选功能」开启“独立权威 DNS 池”后，系统管理员可以让自己的节点直接应答一个区域的 DNS 查询，不经过任何 DNS 服务商 API。数据仍保存在 metadata（`dns_auth_zone:*`、`dns_auth_member:*`、`dns_auth_record:*`），schema v5 与恢复日志格式不变。还有区域时开关不能关闭。

- **区域**：域名（至少两段，不能与池中其他区域重叠）、SOA 管理员邮箱（默认 `hostmaster@区域`）、TTL 与否定缓存 TTL（30–86400 秒，默认 60）、每条记录最少保留的值（0–16，默认 1）。区域、成员或记录的任何改动都会提高 SOA 序列号。
- **名称服务器（成员）**：一个节点 + 标签（默认 `ns1`、`ns2`…，主机名为 `标签.区域`）+ 1–4 个具体监听 IP（拒绝 `0.0.0.0`/`::` 等通配地址）+ 对外公布地址（作为 glue；云 NAT 后面时填公网 IP，监听内网 IP）+ 端口（默认 53）。每个区域最多 8 个成员，同一节点在一个区域只能出现一次；仍是成员的节点不能删除。
- **记录**：相对名称（`@` 为区域本身，不支持通配符）、类型 A/AAAA/CNAME/TXT、可选 TTL、1–16 个值。每个值可以绑定一个节点规则作健康门控，判定与上文健康摘除相同（心跳 90 秒内、至少一个 eligible healthy 目标；未知或过期一律视为不健康）。健康的值全部应答；不足“最少保留”时按填写顺序补回。CNAME 只能有一个值、不能在区域本身、不能与其他记录同名；与名称服务器同名的 A/AAAA/CNAME 会被拒绝（其地址来自成员）。

**下发与应答**

- 控制器每次同步都为成员节点渲染应答（使用最新的健康报告），放在 `SyncResponse.authoritative_dns`；非成员或开关关闭时发送空内容，Agent 随即停止监听。旧 Agent 忽略这个字段；旧控制器不发送，新 Agent 视为空。
- Agent 在每个监听 IP 上打开 UDP 和 TCP（IPv6 套接字只接 IPv6），只应答标准查询，置权威位、不提供递归。区域内的 CNAME 会继续解析；不存在的名称返回 NXDOMAIN，存在但无此类型返回 NOERROR，两者都带 SOA；不在任何区域的名称返回 REFUSED；AXFR/IXFR 拒绝；ANY 只返回 A/AAAA。支持 EDNS（最大 1232 字节），超过客户端可接收大小时置 TC 让客户端改用 TCP。UDP 按来源 /24（IPv6 /56）限速（每秒 200 个、突发 400），降低反射放大风险；TCP 最多 64 个连接、空闲 10 秒断开。
- Agent 把最近一次收到的应答保存在本地状态里；重启时控制器暂时不可达，也会继续按这份内容应答。
- Agent 只向发送过应答内容的控制器报告 `EngineStats.authoritative_dns`（序号、正在监听的地址、监听错误、查询/NXDOMAIN/REFUSED/截断/限速计数）。面板据此把成员显示为：正在应答、更新中（还在用上一版）、监听失败、等待节点报告（可能是 0.137.0 以前的 Agent）或节点离线。

**服务器准备（需要服务器管理员操作）**

- Agent 以非 root 用户运行，53 端口需要 `CAP_NET_BIND_SERVICE`：把 `deploy/relay-agent-dns.conf` 安装为 `/etc/systemd/system/relay-platform-agent.service.d/dns.conf`，执行 `systemctl daemon-reload && systemctl restart relay-platform-agent`。它只授予绑定低端口的能力。
- 在防火墙放行 UDP 和 TCP 53。systemd-resolved 的本地存根只用 127.0.0.53/127.0.0.54，绑定具体公网/内网 IP 不冲突；如果 dnsmasq、bind 等已经占用该地址的 53 端口，面板会显示“地址已被占用”。

**在注册商委派**

- 先让至少两台位于不同服务器的成员都在应答，用 `dig @对外地址 区域 SOA +norec` 逐台确认，再委派；部分注册局会先检查名称服务器。
- 子域名（推荐）：在上级域名的 DNS 中添加 `区域 NS ns1.区域`、`区域 NS ns2.区域` 以及 `ns1.区域 A 对外地址` 等 glue 记录。面板在区域下方列出可直接复制的记录。
- 整个域名：在注册商创建同名“子名称服务器”（host 对象，带 glue），再把域名的名称服务器改成它们。
- 不支持 DNSSEC：上级不能存在该区域的 DS 记录。用 `dig +trace 名称` 检查委派链。

API 见 [API.md](API.md#0137-authoritative-dns-pool)。

## 验证与限制

- 4 项测试使用本机 mock Cloudflare API，覆盖创建、更新、观察不写、`min_keep` 保留/删除、健康门控的摘除/恢复/心跳过期、令牌脱敏、租户管理员 403、API 令牌 403、DDNS 和删除时清理服务商记录。
- 健康门控测试写入真实的 `nodes.stats_json` 健康报告并核对 `eligible/status/last_seen`；没有启动真实 Agent 产生探测流量。
- 未连接真实 Cloudflare 账户，未验证真实 DNS 传播、分页、速率限制或供应商错误码矩阵。
- 权威 DNS 池：6 项单元测试覆盖应答规则（大小写、区域内/外 CNAME、NODATA 与 NXDOMAIN 带 SOA、REFUSED、SOA/NS/glue、ANY、TC 截断与 EDNS、拒绝非查询报文）和健康补回顺序；2 项端到端测试使用真实控制器 HTTP API、真实 Agent、真实 TCP 健康探测以及真实 UDP/TCP 查询，覆盖开关 409、通配监听 400、CNAME 冲突 409、健康失败后摘除、成员状态与查询计数、控制器离线时 Agent 重启后按保存内容继续应答、删除区域后停止监听、仍是成员的节点不能删除。真实 53 端口、真实注册商委派、公网解析器缓存、多台名称服务器跨地域一致性尚未验收。
- 观察模式下的 DNS webhook、节点公网 IP 自动探测、跨记录最少保留策略、真实 Agent 端到端和污染/缓存测试仍未实现。当前模块状态是“部分实现”，不是完整 DNS 模块验收。

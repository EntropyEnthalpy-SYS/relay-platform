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

## 验证与限制

- 4 项测试使用本机 mock Cloudflare API，覆盖创建、更新、观察不写、`min_keep` 保留/删除、健康门控的摘除/恢复/心跳过期、令牌脱敏、租户管理员 403、API 令牌 403、DDNS 和删除时清理服务商记录。
- 健康门控测试写入真实的 `nodes.stats_json` 健康报告并核对 `eligible/status/last_seen`；没有启动真实 Agent 产生探测流量。
- 未连接真实 Cloudflare 账户，未验证真实 DNS 传播、分页、速率限制、供应商错误码矩阵或权威 DNS 池。
- 观察模式下的 DNS webhook、节点公网 IP 自动探测、跨记录最少保留策略、真实 Agent 端到端和污染/缓存测试仍未实现。当前模块状态是“部分实现”，不是完整 DNS 模块验收。

# DNS 托管记录、健康摘除与 DDNS

0.22.0 增加 DNS 服务商、区域和托管记录；0.23.0 增加入口健康摘除。它解决“平台创建 A/AAAA/CNAME 记录并核对服务商实际状态”的运维需求；不是完整权威 DNS 池，也不会声称 DNS 已传播。

## 数据与安全边界

- 服务商、区域和记录都保存在 `metadata`（`dns_provider:<id>`、`dns_zone:<id>`、`dns_record:<id>`），因此 schema v5、恢复日志格式 4、备份和连续恢复不变。新增字段（服务商 `min_ttl`、区域 `failover_confirm_secs`）都有默认值，旧数据和旧备份照常读取。
- 确认窗口的计时、每条记录的状态和区域的最近检查时间只保存在控制器进程内存中，不写 metadata，也不跨重启保留（见下文“自动同步”）。
- 服务商 API 令牌必须可逆保存才能调用外部 API。读取接口只返回 `token_set`，不返回令牌原文；只有系统管理员能读写 DNS。API 令牌即使带 `users:write` 也不能访问 `/dns/*`，只接受登录会话。
- API 基础地址必须是 HTTPS；只有回环地址允许 HTTP，供本机 mock/测试使用。地址中不允许用户名、密码、查询或片段。系统管理员能把控制器指向可达地址，因此该角色本身必须可信。
- 服务商类型为 Cloudflare 兼容 API（`cloudflare`）或 DNS Webhook（`webhook`，见下文“DNS Webhook 服务商”）。服务商 API 返回 `success:false`、非 2xx 或 webhook 未确认应用时记录错误，不用本地期望值伪装成已生效。

## 区域与记录

```json
{
  "provider_id": "…",
  "name": "example.com",
  "mode": "observe",
  "min_keep": 1,
  "failover_confirm_secs": 60
}
```

`name` 用作服务商 API 路径：Cloudflare 需要区域 ID（32 位十六进制），兼容 API 可能也接受名称。面板新增/编辑区域时可以点“读取服务商区域”，从服务商连接测试返回的列表中选择，选中后填入区域 ID；也可以照旧手动填写。

`mode`：

- `observe`：读取服务商记录并报告“将创建/将更新/保留/差异”，不调用写 API，不写服务商。
- `apply`：创建、更新和删除本平台管理的记录。

记录字段：`name`（FQDN 或服务商接受的相对名）、`type`（`A`、`AAAA`、`CNAME`）、`content`、`ttl`（1..86400）、`proxied`、`enabled`。A/AAAA 内容必须是 IP，CNAME 内容必须是主机名。

可选 `health`：`{"node_id":"…","rule_id":"…"}`。填写后同步器要求该节点心跳不超过 90 秒、节点资料为活动状态，并且该规则至少有一个 `eligible=true` 且 `status=healthy` 的目标报告；否则这次检查判定为“失败”。未知、过期、无心跳和停用节点一律 fail closed。更新记录时传 `clear_health:true` 可移除该门控。

**确认窗口**（`failover_confirm_secs`，0..=1800 秒）：健康门控记录要在连续的检查中一直失败满这么久才摘除（观察模式报告 `would-health-remove`，应用模式删除服务商记录），摘除后要一直健康满这么久才重建；期间只要有一次相反的结果，计时就从头开始。“连续”指每次检查（自动 30 秒一次，加上手动同步）看到的结果。检查结果与服务商当前状态一致时（例如被保留的记录又恢复健康，或已不在服务商的记录仍然失败）无需写入，状态立即跟随。新建的健康门控记录同样要先连续健康满一个窗口才会创建。通过 API 新建区域时省略该字段默认 60 秒；本版本之前创建的区域读取为 0，即保持原来“下一次同步立即摘除/重建”的行为，编辑区域时可以调整。

**过半失败保护**：同一区域内同名同类型、启用且带健康门控的值至少有 2 个，并且在同一次检查中**超过一半**失败时，更可能是监控或控制链路出了问题，而不是这些入口真的都坏了，因此暂停这一名称的所有健康摘除：记录保留并报告 `guard`（状态 `held_guard`），区域状态的 `guarded` 列出该名称。正好一半失败时照常摘除。只有一个值的名称不受这项保护，仍由 `min_keep` 兜底。暂停期间确认计时照常进行；失败比例回落后，已满窗口的失败记录会在下一次检查时摘除。停用记录的删除不受这项保护。

每条记录创建时带 `relay:<record id>` 注释。同步时优先按保存的服务商记录 ID 匹配；丢失时按“类型 + 名称 + relay 注释”恢复，不会接管同名但没有本平台注释的外部记录。删除本地记录时，应用模式会先删除对应服务商记录；观察模式只删除本地记录。

`min_keep` 是删除停用/健康摘除记录时的保护：只有当前有效（本地启用，且没有健康门控或确认结果为健康）的托管记录数不少于该值，才删除服务商记录；否则保留并报告 `kept`（状态 `held_min_keep`）。

## 服务商：连接测试与最低 TTL

`POST /api/v1/dns/providers/{id}/test` 用已保存的令牌调用服务商的区域列表（Cloudflare `GET /zones`，每页 50 个，最多 20 页），成功返回：

```json
{"ok": true, "zones": [{"id": "023e105f4ecef8ad9ca31a8372d0c353", "name": "example.com"}], "truncated": false}
```

令牌无效、权限不足或服务商不可达时返回 502 和 `{"error":"DNS provider test failed: DNS provider rejected the request: … (9109)"}`。错误文本中如果出现令牌原文会被替换为 `[redacted]`；令牌本身不会出现在响应、日志或记录错误中。只列出令牌能看到的区域：仅授予 DNS 编辑权限的 Cloudflare 令牌可能看不到区域列表，此时面板仍可手动填写区域 ID。面板在服务商列表提供“测试”按钮。

可选 `min_ttl`（1..=86400；0 或省略表示不限制，`PUT` 传 0 清除）：TTL 低于它的记录按 `min_ttl` 发布，本地记录的 `ttl` 不变，记录状态的 `published_ttl` 显示实际发送的值。TTL 1 是 Cloudflare 的“自动”，任何套餐都接受，因此不会被提高。Cloudflare 对代理（`proxied`）记录总是返回 TTL 1，同步时不再把这一点当作差异，避免每次同步都重写代理记录。

## DNS Webhook 服务商

`kind: "webhook"` 把记录推送到你自己运行的接收端（例如通过 RFC 2136 写 BIND 的适配器，或自写的 DNS API 适配器），由接收端验签并实际写入 DNS。请求格式按 ZeroForwarder 公开文档对其 DNS Webhook 协议 v1 的说明实现（[DNS Webhook 接入](https://www.zeroforwarder.com/docs/dns-webhook/)）。该文档说明完整字段表、状态码与重试规则只在 ZFC 面板内置文档和下载包中提供；本实现没有用其官方接收端核对，差异见本节末尾。

**服务商字段**

- `endpoint`：接收端的最终 URL，原样使用（包括路径和末尾斜杠），没有默认值。规则与 Cloudflare 相同：必须 HTTPS，只有回环地址允许 HTTP；不能含用户名密码、查询或片段。同一 URL 只能配置一个 webhook 服务商（409），因为接收端按来源和集合保存版本。
- `token`：HMAC Secret，至少 32 个 UTF-8 字节，可逆保存，读取只返回 `token_set`，不会出现在响应、日志、审计或记录错误中。
- `zones`：必填，1–100 个 DNS 名称，统一为小写、去掉末尾点并去重；`PUT` 传入时整体替换。仍有区域使用的名称不能移出列表（409），先删除该区域。
- 修改 `endpoint` 视为换了接收端：控制器丢弃该服务商所有区域的确认内容，下一次同步在新地址开始新代次并重推每个集合。旧接收端保留它已写入的内容，需要在那边自行清理。
- `timeout_secs`：每个请求的超时，1–30 秒，默认 15。`min_ttl` 与 Cloudflare 相同。
- Cloudflare 服务商传 `zones` 或 `timeout_secs` 返回 400。服务商类型保存后不能修改。

**请求**：每个请求都是 `POST endpoint`，`Content-Type: application/json`，带以下请求头：

| 请求头 | 内容 |
| --- | --- |
| `X-ZFC-Event` | 与 body 中的 `event` 相同 |
| `X-ZFC-Delivery` | 每次请求一个新的 UUID |
| `X-ZFC-Timestamp` | 发送时的 Unix 秒 |
| `X-ZFC-Signature` | `sha256=` 加小写十六进制的 HMAC-SHA256：密钥是 Secret 的 UTF-8 字节，输入是“时间戳 + `.` + 原始 body 字节” |

body 有三种：

```json
{"version":1,"source":"<一次性随机 UUID>","event":"ping","zones":["example.com"]}
{"version":1,"source":"<服务商 ID>","event":"generation.start","generation":"3"}
{"version":1,"source":"<服务商 ID>","event":"record_set.put","generation":"3","seq":"17",
 "zone":"example.com","name":"edge.example.com","type":"A","ttl":300,"values":["203.0.113.1","203.0.113.2"]}
```

`generation`、`seq` 是 1..9223372036854775807 的十进制字符串。`values` 是该区域内该名称和类型的**完整集合**（去重，按字节序排列）；`[]` 表示删除该名称的该类型，其他记录不受影响。A/AAAA 值写成规范 IP 文本；记录名和 CNAME 目标统一小写、去掉末尾点。

**响应**

- 2xx（202 除外）表示接收端已经应用。202 视为失败：它表示“已接收但未确认已应用”。
- 3xx 视为失败，且不跟随：签名请求不会被转发到其他地址。请填写最终 URL。
- 其他状态都是失败。错误信息取 JSON 中的 `error`、`code`、`message`、`detail`、`watermark` 字段，或正文的前 300 个字符（最多读取 4 KiB），写入记录的 `last_error` 和同步动作；正文中若出现 Secret 原文会替换为 `[redacted]`。
- 超时报告 `got no answer within N s; the receiver may still apply it`。结果未知时本地不记为已发布，下一次同步按最新期望以新的 `seq` 重新发送完整集合。本次同步内不重试；应用模式区域每 30 秒自动同步一次，差异仍在时会再次发送。

**代次与序号**：`source` 是服务商 ID。控制器进程第一次需要写入某个服务商时，先把保存在 metadata `dns_webhook_source:<服务商 ID>` 的代次加 1 并写回，再发送 `generation.start`；本进程之后对该服务商的 `record_set.put` 都使用这个代次和递增的 `seq`（同一服务商的请求串行发送）。接收端对 `generation.start` 返回 409 并带有更高的 `watermark` 时（例如控制器数据库从备份恢复），控制器改用 `watermark + 1` 重发一次；`record_set.put` 返回 409 时，下一次写入重新开始一个代次。没有变化时不发送任何请求，也不发送 `generation.start`。

**同步语义**：webhook 无法读回，所以“服务商上的记录”就是接收端确认过的内容，按区域保存在 metadata `dns_webhook_zone:<区域 ID>`（每条记录的名称、类型、内容和 TTL），重启后照常读取。比较、确认窗口、过半失败保护、`min_keep` 和最低 TTL 与 Cloudflare 完全相同，只是每次创建、更新或删除一条记录都发送它所在集合的完整值。

- 同名同类型的多个值共用一个 TTL，取其中最低值（RFC 2181 §5.2）；TTL 1 在 webhook 中没有“自动”的含义，会按最低 TTL 抬高。
- 记录改名时先从旧集合移除，再加入新集合；中途失败时它暂时不在 DNS 中，下一次同步补上，不会同时留在两个集合里。
- 同名 CNAME 只能有一个目标；第二个目标在发送前报错。
- 观察模式不联系接收端，只和接收端最近确认的内容比较，因此看不到在 Relay 之外对 DNS 的修改。
- 观察模式下删除本地记录时，接收端确认过的值会保留（与 Cloudflare 留下服务商记录相同），之后该集合的推送仍包含它。

**区域与记录限制**：webhook 区域的名称必须是服务商 `zones` 中的 DNS 名称（不是 ID），同一服务商下每个区域只能创建一次（409）；已有确认内容的区域不能改成另一个名称（409），因为接收端按旧区域名保存这些集合。记录名必须是区域本身或区域内的完整域名（400），不能开启 `proxied`（400）。

**降级**：0.147.0 及更早的控制器不认识 `webhook` 类型。数据库里只要有一个 webhook 服务商，旧版的服务商列表就返回 500，也无法在旧版中删除它（Cloudflare 服务商、区域和记录仍可读写）。降级前请先删除 webhook 区域的记录、区域和服务商本身；如果已经降级，升级回来删除后再降级。

**连接测试**：发送签名的 `ping`（`source` 为一次性随机 UUID，`zones` 为服务商配置的区域），成功返回 `{"ok":true,"zones":[{"id":"example.com","name":"example.com"}],"truncated":false}`；失败返回 502，信息不含 Secret。测试不验证 DNS 写权限，也不证明记录已经公开解析。

**兼容性与差异（相对 ZFC 公开文档）**

- 一致：请求头、签名输入、三种事件及字段、`values` 完整集合语义与 `[]` 删除、十进制字符串的代次和序号、不跟随重定向、成功前不回 2xx、Secret 至少 32 字节、超时 1–30 秒默认 15 秒。
- 本实现自行选择（交接中没有约定，不是用户决定）：`source` 固定为服务商 ID；每次控制器启动后第一次写入时开始新代次，新代次不重推未变化的集合；202 视为失败；409 中接收端代次的字段名按公开文档措辞取 `watermark`（字符串或数字）；错误正文按 `error`/`code`/`message`/`detail` 解析；不立即重试，依靠 30 秒自动同步重发；集合 TTL 取最低值；webhook 服务商需要单独列出区域。
- 未覆盖：ZFC 支持的 TXT、NS 记录和证书 DNS-01（Relay 托管记录只有 A/AAAA/CNAME）；ZFC 面板的“重试失败推送”和接收端离线恢复流程（接收端返回 503 `pending_delivery_requires_recovery` 时记录持续报错，需要按接收端说明处理）；未与 ZFC 下载包中的官方接收端互通测试。

## 同步

`POST /api/v1/dns/zones/{id}/reconcile` 执行一次显式同步，返回：

```json
{
  "zone_id": "…", "mode": "observe", "observed": 2,
  "created": 0, "updated": 1, "deleted": 0, "unchanged": 1,
  "kept": 0, "pending": 0, "guarded": 0, "errors": 0,
  "actions": [{"record_id": "…", "action": "would-update", "detail": "A edge.example.com -> 203.0.113.12"}]
}
```

`created`/`updated`/`deleted` 在观察模式下分别表示“将创建/将更新/将删除”的数量。`pending` 是仍在确认窗口内的健康变化（动作 `pending-remove`/`pending-restore`），`guarded` 是被过半失败保护暂停的摘除（动作 `guard`）。错误逐条写入记录的 `last_error`，成功同步会清除该错误并记录 `last_observed`。这正是“配置提交”和“外部 DNS 接受”的区分：控制器只证明服务商 API 接受了请求，不证明递归解析器、缓存或权威服务器已传播。

每次同步按页读取服务商记录（每页 100 条，最多 50 页）；批量操作和并发冲突重试未实现。

### 自动同步

控制器启动 90 秒后（等 Agent 在一个心跳窗口内重新回报，避免把重启期间的过期心跳当成故障），每 30 秒依次检查所有区域：应用模式写入差异，观察模式只读取服务商并把结果保存为状态，不写服务商。因此健康门控记录会自行摘除和重建，不再需要有人点“立即同步”。

- **调用量有界**：每个区域每次检查读取一次记录列表（通常 1 个请求）；只有存在差异时才调用创建/更新/删除，也只有内容变化时才写 metadata（因而不会每 30 秒产生恢复日志）。按 Cloudflare 每用户 5 分钟 1200 个请求的限额，一个区域每 5 分钟约 10 个读取请求。
- **不与手动同步重叠**：同一区域的自动检查、“立即同步”、DDNS 和删除记录共用一把锁，整个“读取—决定—写入”过程互斥，所以不会两次都看到“服务商没有这条记录”而重复创建。服务商请求超时 30 秒，锁不会被挂起的请求长期占用。
- **错误不中断任务**：服务商不可达、令牌失效等整区错误写入区域状态的 `last_error`；单条写入失败写入记录的 `last_error`；任务继续检查其他区域，下一轮重试。
- **生效延迟**：健康变化在下一次检查时才被看到，确认满窗口后也要等下一次检查执行，所以实际摘除/重建时间约为“确认窗口 + 最多两个检查间隔（60 秒）”。

**状态不跨重启保留**：确认计时、记录状态和区域检查时间只在内存中。重启后第一次检查以服务商当前状态为起点：仍在服务商的记录要重新连续失败满一个窗口才摘除，已摘除的记录要重新连续健康满一个窗口才重建。这样重启只会推迟一次摘除或重建，不会引发一次；同时 30 秒一次的检查不需要写库。代价是重启前已经计了一半的窗口会重新计时。

区域的 `GET /dns/zones`、`GET /dns/zones/{id}` 额外返回 `status`：

```json
{"last_evaluated_ms": 1767225600000, "last_trigger": "automatic", "last_automatic_ms": 1767225600000,
 "last_error": null, "guarded": ["A edge.example.com"]}
```

记录的读取接口额外返回 `status`（尚未检查时为 `null`）：`state` 为 `published`（已发布）、`pending_remove`（失败中，等待确认摘除）、`pending_restore`（恢复中，等待确认重建）、`removed`（因健康门控不在服务商）、`disabled`、`held_min_keep`、`held_guard`、`would_create`/`would_update`/`would_remove`（观察模式）或 `error`；另有 `healthy`（本次健康结果）、`since_ms`（当前连续结果的起点）、`due_at_ms`（等待中的摘除/重建到期时间）、`published_ttl` 和 `evaluated_at_ms`。面板的区域表显示“确认窗口”和“自动检查”（最近一次自动检查时间、整区错误、被暂停摘除的名称），记录表的“状态”列显示上述状态和原因（例如“健康检查已连续失败 25 秒，满 60 秒后摘除”）。

## DDNS

`POST /api/v1/dns/records/{id}/ddns`，请求 `{"content":"203.0.113.31"}`：

1. 只允许 A/AAAA 记录；
2. 更新本地内容；
3. 立即执行该区域一次同步，观察模式只报告差异，应用模式写入服务商。

该接口适合外部脚本按当前公网 IP 调用。它不自动探测节点公网 IP，也不保存历史 IP；接入节点探针/DDNS 调度器是后续工作。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/api/v1/dns/providers` | 列表/创建服务商；`kind` 为 `cloudflare` 或 `webhook`（webhook 另需 `zones`，可选 `timeout_secs`） |
| GET/PUT/DELETE | `/api/v1/dns/providers/{id}` | 读取（令牌脱敏）/更新/删除；可选 `min_ttl`，webhook 可改 `zones`、`timeout_secs`；类型不能改 |
| POST | `/api/v1/dns/providers/{id}/test` | 连接测试，返回可见区域（`id`、`name`）；webhook 发送签名 ping 并返回配置的区域；失败 502 |
| GET/POST | `/api/v1/dns/zones` | 列表（含 `status`）/创建区域；可选 `failover_confirm_secs`（默认 60） |
| GET/PUT/DELETE | `/api/v1/dns/zones/{id}` | 读取（含 `status`）/更新/删除；有记录时删除返回 409 |
| GET/POST | `/api/v1/dns/zones/{id}/records` | 列表/创建记录 |
| GET/PUT/DELETE | `/api/v1/dns/records/{id}` | 读取/更新/删除 |
| POST | `/api/v1/dns/zones/{id}/reconcile` | 显式观察/应用同步 |
| POST | `/api/v1/dns/records/{id}/ddns` | 更新 A/AAAA 并同步 |

所有接口仅系统管理员，审计动作包括 `dns.provider.*`、`dns.zone.*`、`dns.record.*`（连接测试和同步只读取或按已保存配置写服务商，与手动同步一样不写审计）。面板“DNS 管理”页提供新增/编辑/删除、服务商连接测试、从服务商区域列表选择区域、记录列表与状态、立即同步和 DDNS。

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

- 9 项测试使用本机 mock Cloudflare API（mock 和 Cloudflare 一样对代理记录返回 TTL 1），覆盖创建、更新、观察不写、`min_keep` 保留/删除、健康门控的摘除/恢复/心跳过期、令牌脱敏、租户管理员 403、API 令牌 403、DDNS、删除时清理服务商记录，以及：
  - 后台自动同步（真实 `dns::run`，3 秒窗口）：新记录先等待确认再创建；失败未满窗口不摘除，中途一次健康结果让计时重来，满窗口后摘除；恢复后满窗口才重建；记录未变时不写服务商也不改写 metadata；观察模式区域只记录 `would_create`；区域记录最近自动检查时间。
  - 并发：4 个手动/自动同步同时处理同一区域（mock 让每次读取延迟 150 毫秒），只创建一次。
  - 过半失败保护：4 个值中 3 个失败时暂停摘除并在区域状态列出该名称，同时单值名称照常摘除；正好一半失败时照常摘除。
  - 最低 TTL：30 秒按 60 秒发布、TTL 1 和更高的 TTL 不变、代理记录不反复更新；清除最低值后按原 TTL 更新。
  - 连接测试接口：管理员得到区域列表，租户管理员 403，错误令牌返回 502 且包含服务商错误码、不含令牌原文；新区域默认 60 秒窗口，超过 1800 返回 400。
- 4 项单元测试覆盖确认窗口的状态机（零窗口、连续失败/恢复、计时重来、保留记录恢复、更换门控）和 TTL 规则。
- 健康门控测试写入真实的 `nodes.stats_json` 健康报告并核对 `eligible/status/last_seen`；没有启动真实 Agent 产生探测流量。
- 未连接真实 Cloudflare 账户，未验证真实 DNS 传播、速率限制、仅有 DNS 权限的令牌能否列出区域，或供应商错误码矩阵。
- DNS Webhook：5 项集成测试使用本机 mock 接收端（独立实现验签、±300 秒时间窗、按来源的代次水位、按集合的代次/序号与幂等、完整集合替换，并可注入失败、延迟和重定向），覆盖：完整集合与最低 TTL、未变化时零请求、改内容/停用/改名/删除、同名第二个 CNAME 发送前报错、观察模式零请求；重启后不重发且下一次写入开始新代次、接收端代次更高时跳到其上、写入中途 409 后重新开始代次；503/202/401/超时/307 重定向（不跟随）都记为错误且不含 Secret；健康门控的确认窗口、过半失败保护与 `min_keep`；HTTP 接口的输入校验（Secret 长度、明文远程地址、URL 含凭据、缺少区域、超时范围、Cloudflare 不接受 webhook 字段、重复 URL 409）、签名 ping 连接测试与 502、区域必须在列表内且不重复、记录必须在区域内且不能代理、已发布区域不能改名。2 项单元测试用 Python `hmac` 算出的签名核对签名输入，并覆盖名称、值规范化和接收端错误解析。未接入真实 BIND/RFC 2136 或 ZFC 官方接收端。
- 权威 DNS 池：6 项单元测试覆盖应答规则（大小写、区域内/外 CNAME、NODATA 与 NXDOMAIN 带 SOA、REFUSED、SOA/NS/glue、ANY、TC 截断与 EDNS、拒绝非查询报文）和健康补回顺序；2 项端到端测试使用真实控制器 HTTP API、真实 Agent、真实 TCP 健康探测以及真实 UDP/TCP 查询，覆盖开关 409、通配监听 400、CNAME 冲突 409、健康失败后摘除、成员状态与查询计数、控制器离线时 Agent 重启后按保存内容继续应答、删除区域后停止监听、仍是成员的节点不能删除。真实 53 端口、真实注册商委派、公网解析器缓存、多台名称服务器跨地域一致性尚未验收。
- 节点公网 IP 自动探测、跨记录最少保留策略、真实 Agent 端到端和污染/缓存测试仍未实现。当前模块状态是“部分实现”，不是完整 DNS 模块验收。

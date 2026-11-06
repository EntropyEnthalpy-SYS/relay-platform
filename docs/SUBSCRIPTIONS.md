# 客户端订阅

0.21.0 增加用户级客户端订阅：控制器把该用户在启用节点上的 Shadowsocks 入站规则渲染成常见客户端格式，并通过一个独立、可撤销的链接公开。它不把控制器会话、节点凭据或 API 令牌交给客户端；链接只包含节点地址、端口和 Shadowsocks 密钥。

## 数据与安全边界

订阅记录保存在 `metadata` 的 `subscription:<id>`，公开令牌索引保存在 `subscription_token:<sha256>`。因此 schema v5、恢复日志格式和备份流程不变；记录随控制器数据库、备份和连续恢复日志一起保存。令牌使用 `rsub_` 加 32 字节随机十六进制，只保存 SHA-256 哈希，创建或轮换时返回一次明文。

- 每个用户最多 20 个订阅；名称 1..120 字节。
- 到期时间 1..3650 天。过期、删除、轮换后的旧令牌（宽限期外）、所属用户被停用或删除、请求来源不在 `allow_sources` 内时，公开端点返回 401，不返回节点信息。
- 公开端点按令牌限频：60 次/分钟，进程内计数，重启清零。它不替代反向代理或出口限频。
- 任何持有链接的人都可以读取连接参数，因此应把链接当作密码；泄露后立即在面板轮换或删除。令牌出现在 URL 路径中，反向代理访问日志可能记录它；生产部署应关闭或脱敏该路径的查询/路径日志。
- 公开端点只返回内容，不需要登录；管理 API 需要登录会话或带范围的 API 令牌。读取列表和预览需要 `read`，创建/编辑/轮换/删除需要 `users:write`，并仍受账号角色与租户边界限制。只读用户不能创建、编辑、轮换或删除。
- 系统管理员可管理所有订阅；租户管理员可管理本租户普通用户的订阅；普通用户只能管理自己的订阅。租户管理员不能管理系统管理员的订阅。

## 支持的格式

只包含**启用中的 Shadowsocks 入站**规则（`inbound_shadowsocks` 非空）。普通 TCP/TLS/WS/WSS 规则不是客户端代理协议，会在预览的 `skipped` 列表中写明原因，而不是静默消失。

| 格式 | 输出 | 说明 |
| --- | --- | --- |
| `v2ray` | 标准 Base64，解码后每行一个 `ss://` URI | 适合 v2rayN、Shadowrocket、sing-box 等支持 SIP002 的客户端 |
| `clash` | Clash / mihomo YAML：`proxies`、`proxy-groups`、`rules` | 使用 `type: ss`、`cipher`、`password`、`udp`；组名固定为 `Relay` |
| `surge` | 完整的 Surge 托管配置：`[General]`、`[Proxy]`、`[Proxy Group]`、`[Rule]`，见下方「Surge 完整配置」 | 逗号或换行密码、IPv6 地址会单独处理；Surge 手册列出 2022 方式中的 `2022-blake3-aes-128-gcm` 与 `2022-blake3-aes-256-gcm` |
| `shadowrocket` | 每行一个 `ss://` URI | 可直接导入 Shadowrocket |

2022 方式 URI 使用 `method:password` 的 URL 编码；旧版 AEAD 使用 `base64url(method:password)`，与面板现有分享链接一致。URI 片段使用节点名和规则名生成显示名。

### Surge 完整配置

Surge 订阅是一份可以直接安装、使用的完整配置，Surge 的三种出站模式（规则判定、全局代理、直接连接）都能直接切换：

- 公开链接返回的第一行是 `#!MANAGED-CONFIG <订阅链接> interval=86400 strict=false`，Surge 据此把它当作托管配置，每天自动更新；更新失败时继续使用旧配置。链接使用客户端访问时的地址：反向代理转发的 `Host`，加上 `X-Forwarded-Proto: https` 时的 `https`（否则为 `http`）。面板部署在子路径下时这一行不正确。`Host` 含有无法写入这一行的字符时不写这一行，配置仍可使用但不会自动更新。登录后的预览不含这一行，因为预览不知道订阅令牌。
- `[General]`：`loglevel = notify`、`dns-server = system`，`skip-proxy` 让本机、局域网和 `*.local` 绕过系统代理，`exclude-simple-hostnames = true`；连通性测试使用 `http://www.apple.com/library/test/success.html`（直连）和 `http://www.gstatic.com/generate_204`（代理）。
- `[Proxy Group]`：
  - `Relay`：主选择组。先列出你自己的代理（代理链），再列出 `Auto`、`Fallback` 和各中转条目；默认使用第一项，没有自己的代理时默认 `Auto`。
  - `Auto`（`url-test`）：自动使用延迟最低的中转条目。`Fallback`（`fallback`）：按顺序使用第一个可用的中转条目。
  - `Relay entry`：只在有代理链时出现，见上一节。
  - `Mainland China`：中国大陆的网站和 IP 走哪里，默认 `DIRECT`（直连），可在 Surge 里切换为 `Relay`。
- `[Rule]`（规则判定模式下生效，按顺序匹配）：`RULE-SET,SYSTEM,DIRECT`（Apple 系统服务直连）、`RULE-SET,LAN,DIRECT`（局域网直连）、`DOMAIN-SUFFIX,cn` 与 `GEOIP,CN` 交给 `Mainland China`，其余 `FINAL,Relay,dns-failed`。`LAN` 和 `GEOIP` 规则会先在本机解析域名；解析失败时 `dns-failed` 让请求直接走 `Relay`。
- 组名与条目名冲突时追加 `_`，`FINAL` 和 `Mainland China` 指向改名后的主组。

## 模板快照

创建或编辑时保存：

```json
{
  "name_prefix": "Relay ",
  "host": null,
  "node_tags": ["prod"],
  "udp": true
}
```

- `name_prefix`：客户端显示名前缀，0..64 字节。
- `host`：覆盖所有条目的连接地址，用于 NAT 或统一域名；留空时优先使用规则的 `advertise`，其次使用具体监听 IP。通配监听且没有 `advertise`/`host` 的规则会被跳过。
- `node_tags`：只包含带任一标签的节点；空数组表示全部活动节点。
- `udp`：在客户端侧声明 UDP；实际能否使用还取决于规则协议和客户端。
- 端口段规则会展开为每个端口一个条目，`advertise` 端口按偏移递增，名称带端口后缀。超过 65535 的偏移会被跳过。

模板在创建或编辑时作为记录的一部分保存（轮换不改变模板）；节点之后改名、改标签或改地址不会重写已生成的订阅内容，只有重新渲染（客户端再次拉取）时才按当前节点配置生成。这使“模板快照”与实时节点状态有明确边界：快照保存的是显示选项，不冻结节点地址。

## 代理链：经中转节点连接你自己的代理

模板可带 `upstreams`：用户自己的 SOCKS5 或 Shadowsocks 代理，最多 8 个。订阅为每个代理生成一个客户端条目，客户端经本订阅的中转条目连接它：客户端 → 中转节点 → 你的代理 → 目标网站。代理链由客户端组装，节点配置不变；中转节点只看到一条到 `server:port` 的普通代理连接。

```json
"upstreams": [
  {"name": "Home", "type": "socks5", "server": "home.example.net", "port": 1080, "username": "alice", "password": "…"},
  {"name": "Office", "type": "shadowsocks", "server": "203.0.113.9", "port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "…"}
]
```

- `name`：1..64 字节，不能重复；与中转条目同名时按现有规则追加 ` #2` 等后缀。
- `type`：`socks5` 的用户名和密码要么同时填写，要么都省略，不能带 `method`；`shadowsocks` 必须带 `method` 和 `password`，不能带 `username`，2022 方式的密钥按方法长度校验。
- `server` 与模板 `host` 使用同一校验；`port` 为 1..65535；用户名和密码 1..255 字节，不含控制字符。

| 格式 | 代理条目 |
| --- | --- |
| `sing_box` | `socks`（`version: "5"`）或 `shadowsocks` 出站，`detour` 指向选择器 `Relay entry` |
| `clash` | `type: socks5` 或 `ss`，`dialer-proxy: Relay entry` |
| `surge` | `socks5` 或 `ss` 行，`underlying-proxy=Relay entry` |
| `v2ray`、`shadowrocket` | 无法表达代理链；每个代理列入 `skipped` |

带代理时会多一个选择组 `Relay entry`，只包含中转条目，用来选择链的第一跳。主组 `Relay` 先列出你的代理，再列出中转条目，客户端默认使用第一个代理。组名与条目名冲突时追加 `_`。没有任何中转条目时，代理同样列入 `skipped`。Surge 无法表示用户名或密码中的逗号，这类代理在 Surge 格式中跳过。

- 你的代理必须能从中转节点访问。节点入站默认拒绝内网和回环目的地（`allow_private_destinations: false`）。
- 代理凭据随订阅记录保存，和中转条目的密钥一样出现在生成内容中：任何持有订阅链接的人，以及能预览该订阅的管理员，都能读到它们。
- 代理随订阅一起编辑（见「编辑订阅」），链接不变。
- sing-box 的 `detour` 会让该出站的其他拨号字段失效，所以代理条目不写 `udp_fragment`。UDP 能否经整条链转发取决于客户端和代理本身。
- 不含 `upstreams` 的记录序列化结果不变，旧版本仍可读取。0.141.5 及更早版本的模板拒绝未知字段：只要存在一条带 `upstreams` 的订阅，旧版本的订阅列表接口就会整体报错，该订阅链接也无法渲染。回退到这些版本前，先删除带代理的订阅。

## 编辑订阅

`PUT /api/v1/subscriptions/{id}` 修改订阅设置，令牌不变，已导入的客户端下次拉取即得到新内容：

```json
{"name": "手机", "format": "clash", "template": {"name_prefix": "Relay ", "node_tags": ["hk"]}, "allow_sources": ["203.0.113.0/24"], "expires_in_days": 30}
```

- 请求体是完整设置：`name`、`format` 必填；省略 `template` 或 `allow_sources` 会恢复默认值（默认模板、不限来源），与创建时相同。`expires_in_days` 省略时保留当前到期时间，填写时从现在起重新计算（1..3650 天）。不接受 `token`、`user_id` 等其他字段。
- 令牌、所有者、创建时间、使用次数与最近使用时间不变；返回更新后的订阅元数据。审计动作 `subscription.update`。
- 权限与创建相同：须能管理该订阅（系统管理员、本租户普通用户订阅的租户管理员、本人），且非本人时须能为该所有者创建订阅；只读账号和 `read` 范围的 API 令牌返回 403。设置无效时返回 400 且不修改记录。
- 面板订阅列表的「编辑」使用创建表单，预填当前设置；“有效天数”留空表示保持当前到期时间。

## 来源限制

`allow_sources` 是可选的 CIDR 列表（最多 64 个，如 `203.0.113.0/24`、`2001:db8::/32`；单个地址写 `/32` 或 `/128`，面板会自动补全）。空列表不限制来源。

- 客户端地址与登录限频使用同一规则：TCP 对端是回环地址（同机反向代理）时，取最后一个 `X-Forwarded-For` 条目，即代理追加的访问者地址；更早的条目是客户端自述，不采用；来自其他主机的请求不信任该头，直接使用对端地址。IPv4 映射的 IPv6 地址按 IPv4 比较。
- 反向代理在其他主机时，控制器看到的是代理地址；此时只能按代理地址限制，或把代理部署在控制器同机。
- 不在列表内的来源得到与未知令牌完全相同的响应（401 与相同正文），不暴露链接是否存在，也不计入使用次数。按令牌的限频照常计数，因此持有链接的其他来源仍可能占用该令牌每分钟 60 次的额度。
- 来源限制只作用于公开拉取，不影响登录后的预览。

## 轮换宽限期

`POST /api/v1/subscriptions/{id}/rotate` 可带 `{"grace_minutes": n}`（0..1440）。省略请求体或 `0` 与原来相同：旧令牌立即失效。

- `n > 0` 时，被替换的令牌在 `n` 分钟内仍可拉取，便于逐台更换客户端；新旧令牌返回同样的内容，并受同样的来源限制和有效期约束。
- 只保留被本次轮换替换的那个令牌：宽限期内再次轮换时，更早的令牌立即失效。
- 记录只保存旧令牌的 SHA-256（`previous_token_hash`）和期满时间（`previous_token_expires_at_ms`），索引 `subscription_token:<旧哈希>` 保留到期满。期满后第一次用旧令牌访问时删除该索引并清除记录中的旧哈希；删除订阅时两条索引一起删除。
- 订阅元数据返回 `previous_token_expires_at_ms`（无宽限时为 `null`）；面板在到期列显示“轮换前的旧链接有效至 …”。轮换仍会重置使用次数。

## 用量与到期头（`Subscription-Userinfo`）

公开拉取在 Relay 知道所有者的额度或套餐时返回：

```text
Subscription-Userinfo: download=5368709120; total=107374182400; expire=1798761600
```

每一项的含义：

| 项 | 来源 | 何时省略 |
| --- | --- | --- |
| `upload` | 不发送。共享额度按上下行合计计量，无法如实拆分方向；客户端把缺失项当作 0 | 总是 |
| `download` | 所有者 user 范围共享额度（含套餐权益绑定的额度）的 `consumed_bytes`：控制器已确认、去重的上下行合计接纳字节。不含尚未归还的预留（`committed_bytes - consumed_bytes`）。客户端按 `upload + download` 计算已用量，结果与额度一致 | 所有者没有 user 额度 |
| `total` | 该额度的 `limit_bytes` | 没有 user 额度；或套餐不限流量（上限为计数器最大值） |
| `expire` | 套餐权益的到期时间（`expires_at_ms`），Unix 秒，向下取整 | 没有套餐权益；或套餐因全部退款提前失效、记录的到期时间仍在未来 |

- 两者都没有时不发送此头。租户和节点额度与其他用户共享，不计入。
- 订阅链接自己的有效期不写入 `expire`：链接到期只停止更新配置，不停止节点服务。
- 数值是拉取时控制器的视图。节点按预留批次上报，客户端看到的已用量可能落后于实际。
- 登录后的预览不含此头。见 [BUDGETS.md](BUDGETS.md) 与 [COMMERCE.md](COMMERCE.md)。

## API

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/v1/subscriptions` | 列出可见订阅（不含令牌） |
| POST | `/api/v1/subscriptions` | `{name,format,template,expires_in_days,user_id?,allow_sources?}`；返回 `{subscription,token}` |
| GET | `/api/v1/subscriptions/{id}` | 读取一条订阅的元数据 |
| PUT | `/api/v1/subscriptions/{id}` | `{name,format,template?,allow_sources?,expires_in_days?}`；修改设置，令牌不变；返回订阅元数据 |
| GET | `/api/v1/subscriptions/{id}/preview` | 返回 `{content,content_type,entries,skipped}`，用于登录预览 |
| POST | `/api/v1/subscriptions/{id}/rotate` | 可选 `{grace_minutes}`（0..1440）；生成新令牌，旧令牌立即失效或在宽限期后失效；返回 `{subscription,token}` |
| DELETE | `/api/v1/subscriptions/{id}` | 删除记录与令牌索引（含宽限期内的旧令牌） |
| GET | `/sub/{token}` | 公开读取渲染内容；无登录、`Cache-Control: no-store`，按需带 `Subscription-Userinfo` |

公开响应内容类型：Clash 为 `text/yaml; charset=utf-8`，其余为 `text/plain; charset=utf-8`。订阅没有兼容条目时返回 409，预览则返回 200 和完整的 `skipped` 原因。

## 限制与后续

- 真实 Clash/mihomo、Surge、Shadowrocket、v2rayN 客户端互通矩阵尚未执行；测试覆盖生成结构、YAML 解析、URI/Base64 解码、HTTP 端点、权限、轮换、限频和跳过原因。
- 只有 Shadowsocks 入站；VLESS/REALITY、Hysteria2、TUIC、AnyTLS、SOCKS5 等协议待实现后再接入。
- 模板版本化、按订阅统计流量、订阅专用限速档位、实时节点地址变更通知、公开端点持久化限频和反向代理审计尚未完成。
- 订阅记录写入 metadata，schema 保持 v5；0.20.0 二进制会忽略这些键，回退后订阅端点消失但数据仍在。新版本不应在未评估该回退影响时降级。
- `allow_sources`、`previous_token_hash` 和 `previous_token_expires_at_ms` 是带默认值的可选记录字段：已有订阅照常读取，不使用这些功能的记录序列化不变。回退到不认识这些字段的版本时，它们被忽略：**来源限制不再生效**，宽限期内的旧令牌立即失效。回退前先为限制来源的订阅轮换或删除链接。

## 验证

```sh
python3 scripts/check_subscriptions.py --binary target/release/relay \
  --output artifacts/subscription-check.json
```

脚本启动真实控制器和临时状态，发布一条 Shadowsocks 规则与一条普通 TCP 规则，创建四种格式的订阅并访问公开端点；用 Python `PyYAML` 独立解析 Clash、用标准库 Base64 解码 V2Ray，核对 Surge/Shadowrocket 文本、预览跳过普通规则、轮换后旧链接 401、删除后 401。它不启动真实客户端，也不访问外网。结果记录在 `docs/VALIDATION.md`；Clash/mihomo、Surge、Shadowrocket、v2rayN 的客户端导入矩阵仍待独立验收。

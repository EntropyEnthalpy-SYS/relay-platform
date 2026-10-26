# 客户端订阅

0.21.0 增加用户级客户端订阅：控制器把该用户在启用节点上的 Shadowsocks 入站规则渲染成常见客户端格式，并通过一个独立、可撤销的链接公开。它不把控制器会话、节点凭据或 API 令牌交给客户端；链接只包含节点地址、端口和 Shadowsocks 密钥。

## 数据与安全边界

订阅记录保存在 `metadata` 的 `subscription:<id>`，公开令牌索引保存在 `subscription_token:<sha256>`。因此 schema v5、恢复日志格式和备份流程不变；记录随控制器数据库、备份和连续恢复日志一起保存。令牌使用 `rsub_` 加 32 字节随机十六进制，只保存 SHA-256 哈希，创建或轮换时返回一次明文。

- 每个用户最多 20 个订阅；名称 1..120 字节。
- 到期时间 1..3650 天。过期、删除、轮换后的旧令牌、所属用户被停用或删除时，公开端点返回 401，不返回节点信息。
- 公开端点按令牌限频：60 次/分钟，进程内计数，重启清零。它不替代反向代理或出口限频。
- 任何持有链接的人都可以读取连接参数，因此应把链接当作密码；泄露后立即在面板轮换或删除。令牌出现在 URL 路径中，反向代理访问日志可能记录它；生产部署应关闭或脱敏该路径的查询/路径日志。
- 公开端点只返回内容，不需要登录；管理 API 需要登录会话或带范围的 API 令牌。读取列表和预览需要 `read`，创建/轮换/删除需要 `users:write`，并仍受账号角色与租户边界限制。只读用户不能创建、轮换或删除。
- 系统管理员可管理所有订阅；租户管理员可管理本租户普通用户的订阅；普通用户只能管理自己的订阅。租户管理员不能管理系统管理员的订阅。

## 支持的格式

只包含**启用中的 Shadowsocks 入站**规则（`inbound_shadowsocks` 非空）。普通 TCP/TLS/WS/WSS 规则不是客户端代理协议，会在预览的 `skipped` 列表中写明原因，而不是静默消失。

| 格式 | 输出 | 说明 |
| --- | --- | --- |
| `v2ray` | 标准 Base64，解码后每行一个 `ss://` URI | 适合 v2rayN、Shadowrocket、sing-box 等支持 SIP002 的客户端 |
| `clash` | Clash / mihomo YAML：`proxies`、`proxy-groups`、`rules` | 使用 `type: ss`、`cipher`、`password`、`udp`；组名固定为 `Relay` |
| `surge` | Surge 文本：`[Proxy]`、`[Proxy Group]`、`[Rule]` | 逗号或换行密码、IPv6 地址会单独处理；2022 方式是否被具体 Surge 版本接受取决于客户端 |
| `shadowrocket` | 每行一个 `ss://` URI | 可直接导入 Shadowrocket |

2022 方式 URI 使用 `method:password` 的 URL 编码；旧版 AEAD 使用 `base64url(method:password)`，与面板现有分享链接一致。URI 片段使用节点名和规则名生成显示名。

## 模板快照

创建时保存：

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

模板在创建/轮换时作为记录的一部分保存；节点之后改名、改标签或改地址不会重写已生成的订阅内容，只有重新渲染（客户端再次拉取）时才按当前节点配置生成。这使“模板快照”与实时节点状态有明确边界：快照保存的是显示选项，不冻结节点地址。

## API

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/v1/subscriptions` | 列出可见订阅（不含令牌） |
| POST | `/api/v1/subscriptions` | `{name,format,template,expires_in_days,user_id?}`；返回 `{subscription,token}` |
| GET | `/api/v1/subscriptions/{id}` | 读取一条订阅的元数据 |
| GET | `/api/v1/subscriptions/{id}/preview` | 返回 `{content,content_type,entries,skipped}`，用于登录预览 |
| POST | `/api/v1/subscriptions/{id}/rotate` | 生成新令牌并使旧令牌立即失效；返回 `{subscription,token}` |
| DELETE | `/api/v1/subscriptions/{id}` | 删除记录与令牌索引 |
| GET | `/sub/{token}` | 公开读取渲染内容；无登录、`Cache-Control: no-store` |

公开响应内容类型：Clash 为 `text/yaml; charset=utf-8`，其余为 `text/plain; charset=utf-8`。订阅没有兼容条目时返回 409，预览则返回 200 和完整的 `skipped` 原因。

## 限制与后续

- 真实 Clash/mihomo、Surge、Shadowrocket、v2rayN 客户端互通矩阵尚未执行；测试覆盖生成结构、YAML 解析、URI/Base64 解码、HTTP 端点、权限、轮换、限频和跳过原因。
- 只有 Shadowsocks 入站；VLESS/REALITY、Hysteria2、TUIC、AnyTLS、SOCKS5 等协议待实现后再接入。
- 模板版本化、按订阅统计流量、订阅专用限速档位、实时节点地址变更通知、公开端点持久化限频和反向代理审计尚未完成。
- 订阅记录写入 metadata，schema 保持 v5；0.20.0 二进制会忽略这些键，回退后订阅端点消失但数据仍在。新版本不应在未评估该回退影响时降级。

## 验证

```sh
python3 scripts/check_subscriptions.py --binary target/release/relay \
  --output artifacts/subscription-check.json
```

脚本启动真实控制器和临时状态，发布一条 Shadowsocks 规则与一条普通 TCP 规则，创建四种格式的订阅并访问公开端点；用 Python `PyYAML` 独立解析 Clash、用标准库 Base64 解码 V2Ray，核对 Surge/Shadowrocket 文本、预览跳过普通规则、轮换后旧链接 401、删除后 401。它不启动真实客户端，也不访问外网。结果记录在 `docs/VALIDATION.md`；Clash/mihomo、Surge、Shadowrocket、v2rayN 的客户端导入矩阵仍待独立验收。

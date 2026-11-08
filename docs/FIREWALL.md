# 防火墙规则集

规则原有的来源列表（`allow_sources` / `deny_sources`）和目的地列表（`allow_destinations`、`deny_destinations`、`allow_destination_ports`、`deny_destination_ports`，见 [DESTINATION_ACL.md](DESTINATION_ACL.md)）只属于一条规则。**防火墙规则集**是保存在控制器上的命名规则列表：编辑一次，所有使用它的服务器和规则都会更新。它对应 ZeroForwarder 文档中的“防火墙规则集”。

```text
客户端 → [服务器入站规则集] → [规则的入站规则集] → [规则自身的来源列表] → 规则
规则 → [规则自身的目的地列表] + [服务器出站规则集] → 目标 / 代理目的地 / 出口代理上游
```

每一层都必须允许，任何一层拒绝即拒绝。后面的层只能收紧前面的判断，不能放宽。

## 字段

规则集（`GET/POST /api/v1/firewall/sets`）：

```json
{
  "name": "办公网与黑名单",
  "scope": "system",
  "direction": "inbound",
  "default_action": "allow",
  "rules": [
    { "action": "allow", "match": { "sources": ["198.51.100.7/32"] } },
    { "action": "deny",  "match": { "sources": ["198.51.100.0/24", "2001:db8::/32"] } }
  ]
}
```

| 字段 | 含义 |
| --- | --- |
| `name` | 1 到 120 个字符，首尾不能是空格，不含控制字符 |
| `scope` | `system`（系统规则集，绑定到服务器）或 `tenant`（租户规则集，绑定到该租户的规则）；只在创建时设置，默认 `tenant` |
| `tenant_id` | 租户规则集所属的租户；系统管理员创建时可指定，默认是自己的租户。系统规则集没有租户 |
| `direction` | `inbound`（匹配客户端来源）或 `outbound`（匹配服务器要连接的目的地）。**创建后不能修改**（修改返回 400） |
| `default_action` | `allow` 或 `deny`：没有规则匹配时的结果 |
| `rules` | 0 到 256 条规则，按列表顺序检查；列表顺序就是优先级 |
| `rules[].action` | `allow` 或 `deny` |
| `rules[].match.sources` | 入站规则：1 到 256 个 IPv4 / IPv6 地址或 CIDR |
| `rules[].match.destinations` | 出站规则：最多 256 个 IP、CIDR、精确域名或 `*.后缀` 域名 |
| `rules[].match.ports` | 出站规则：最多 256 个端口（`443`）或端口范围（`8000-8080`） |

返回值另有 `id`、`revision`、`created_at_ms`、`updated_at_ms`，以及 `bindings`（使用位置：`{layer, node_id, node_name, rule_id?, rule_name?}`）。

- 入站规则只能写 `sources`；出站规则只能写 `destinations` 和 / 或 `ports`，两者都写时须同时满足，至少写一个。方向不符的匹配条件返回 **400**，例如 `rule 1: an inbound set matches source addresses only, not destinations or ports`。
- `*` 不能作为目的地或端口：需要“全部”时使用默认动作。
- 更新（`PUT /firewall/sets/{id}`）发送完整内容，可带 `expected_revision`；规则集已被他人修改时返回 **409** `the rule set changed; reload before saving`。`scope` 和 `tenant_id` 不能修改。

## 匹配与判定

- **第一条匹配的规则决定**，后面更宽的规则不再起作用；没有规则匹配时使用 `default_action`。空规则集只有默认动作。
- 来源匹配同时比较 IPv4 地址和它的 IPv4 映射 IPv6 形式：`::ffff:192.0.2.1` 与 `192.0.2.1` 匹配同样的网段，写成 `::ffff:192.0.2.0/120` 的条目也匹配 IPv4 客户端。
- 端口范围包含两端：`8000-8080` 匹配 8000 和 8080，不匹配 7999 和 8081。
- `*.example.com` 只匹配子域名（`a.example.com`、`a.b.example.com`），**不匹配** `example.com` 本身，也不匹配 `badexample.com`；需要两者时各写一条。域名不区分大小写，末尾的点被忽略。
- 名称条目只比较客户端发来的名称本身。解析器如果使用搜索域（例如 resolv.conf 的 `search`），`db` 这样的短名称或先得到 NXDOMAIN 的名称可能被补全成另一个完整名称（例如 `db.internal.corp`）再解析，从而避开 `*.internal.corp` 这样的名称条目；本服务器解析和出口代理上游解析都可能如此。要可靠地挡住内部服务，请用 IP / CIDR 条目拒绝内部地址段。
- 控制器（规则测试）和 Agent 使用同一份判定代码（`crates/relay-platform/src/firewall.rs`），按同一份策略计算，所以测试结果与 Agent 的实际行为一致。

### 出站：域名与多个地址

出站规则集在下文“出站覆盖范围”列出的拨号之前按真实目的地检查，方式与目的地 ACL 相同（反向隧道等例外见“不在范围内”）：

- 目的地是域名时，先解析，再对**每个解析出的地址**分别判定（域名条目匹配这个域名的所有地址，IP / CIDR 条目只匹配落在其中的地址）。被拒绝的地址从候选中去掉，只连接允许的地址；全部被拒绝时拒绝连接，不会因为“某个地址允许”而放行其他地址。
- 出口代理的规则把域名原样交给上游时（见 [EGRESS_PROXY.md](EGRESS_PROXY.md)），先只凭域名和端口判定。如果在决定之前有一条含 IP / CIDR 条目的规则可能匹配，只凭域名无法判断，Agent 改为在本机解析，再按地址逐个判定，只把允许的 IP 发给上游。
- 只有**合法的主机名**（由 ASCII 字母、数字、连字符和下划线组成的 1–63 字符标签，以点分隔，总长不超过 253；判定时忽略大小写、首尾空白、方括号和末尾的点）才会只凭名称判定、原样交给上游。其他名称（例如含 NUL 字节的 `db.internal.corp\0`：`*.internal.corp` 条目不匹配它，上游的解析器却可能把它读成 `db.internal.corp`；以及含非 ASCII 字符的原始 UTF-8 名称，上游可能把其中的全角句点等映射成别的名称）与不经出口代理时一样在本机解析，按地址判定。规则自身目的地列表的“只凭名称放行”同样只对合法主机名成立。
- 规则自身的目的地列表在出站规则集之后检查；两者都允许才连接。

## 绑定位置（层）

| 层 | 绑定方式 | 规则集 | 检查对象 |
| --- | --- | --- | --- |
| 服务器入站 | `PUT /nodes/{id}/firewall` 的 `inbound_set_id` | 系统、入站 | 这台服务器所有规则的客户端来源 |
| 规则入站 | 规则的 `firewall_inbound_set` | 该规则租户的租户规则集、入站 | 这条规则的客户端来源 |
| 服务器出站 | `PUT /nodes/{id}/firewall` 的 `outbound_set_id` | 系统、出站 | 这台服务器为转发发起的连接（范围和例外见下文“出站覆盖范围”“不在范围内”） |

**入站顺序**：服务器入站 → 规则入站 → 规则自身的 `allow_sources` / `deny_sources`。TCP 在接受连接时检查，UDP 对每个数据报检查。

**PROXY protocol**：启用 PROXY 输入的规则，服务器入站规则集检查两次：先检查发送报头的连接对端（例如前面的负载均衡器），再检查报头中的客户端地址；规则入站规则集和规则自身的来源列表只检查报头中的客户端地址。信任哪些发送方（`trusted_sources`）由规则的发布者决定，可以是 `0.0.0.0/0`，所以报头不能替发送方通过服务器的规则集。**在服务器前面放负载均衡器时，服务器入站规则集必须允许负载均衡器自己的地址**，否则它转来的所有连接都被拒绝；拦截记录的来源是负载均衡器的地址。

**SOCKS5 BIND**：连接到 BIND 端口的对端也是客户端，同样要通过服务器入站和规则入站规则集以及规则自身的来源列表。被拒绝的对端被断开，BIND 继续等待其他对端直到超时；与规则自身来源列表的拒绝相同，不写拦截记录。

**SOCKS5 UDP**：UDP ASSOCIATE 的中继端口只接受第一个数据报的发送方。这个发送方同样要通过服务器入站、规则入站规则集和规则自身的来源列表；被拒绝的数据报被丢弃并写入拦截记录，关联仍留给之后通过检查的客户端。

**出站覆盖范围**：固定目标（含预热连接、多路径、UDP 目标）、SOCKS5 / HTTP CONNECT / HTTP/2 CONNECT / Shadowsocks 客户端请求的目的地（含 Shadowsocks UDP、SOCKS5 UDP 和 BIND 对端），以及**出口代理的上游地址**。出口代理上游的选择：上游地址也是这台服务器发起的连接，所以同样受出站规则集约束；被拒绝的上游会被跳过，按顺序尝试下一个，全部被拒绝时拒绝客户端并记录拦截。目的地本身仍按上文检查。

不在范围内：协议网关（VLESS / Reality / Hysteria2 等）的客户端由协议引擎检查，规则不能绑定入站规则集（400），服务器入站规则集也不作用于它们。Agent 自己的连接（与控制器同步、WireGuard、目标健康探测）不受规则集约束，与目的地 ACL 相同。反向隧道（[REVERSE_TUNNELS.md](REVERSE_TUNNELS.md)）的流量不受出站规则集约束：公网端把连接交给隧道，不发起拨号；私有端的 Agent 直接连接目标，不检查它自己的出站规则集。公网端的入站层照常检查。

**生效时机**：规则集只判定新连接（UDP 为之后的每个数据报）。编辑规则集内容或修改服务器绑定不会断开已建立的 TCP 连接和代理隧道。修改一条规则的 `firewall_inbound_set` 与修改它的目的地列表一样，会结束这条规则已有的会话。

缺失或方向不符的规则集（例如 Agent 还没有收到新策略中的规则集）在该层拒绝全部连接，不会放行。

## 拦截记录

被规则集拒绝的连接写入拦截记录（[CONNECTIONS.md](CONNECTIONS.md)），原因是 `firewall`，详情只写层、规则序号（从 1 开始）或默认动作，以及规则集名称，不含地址以外的任何敏感内容：

```text
server inbound rule set: rule 2 denies (办公网与黑名单)
rule inbound rule set: default action denies (Office only)
server outbound rule set: rule 1 denies (No mail)
egress proxy 203.0.113.20:1080: server outbound rule set: rule 1 denies (No mail)
```

与其他原因相同，同一规则、同一来源 IP、同一原因在第一条记录后 60 秒内的拒绝合并为一条记录并计数，保留第一条的详情；这段时间内被其他层或其他规则拒绝的详情不会另起一条。面板把详情翻译为界面语言。

## 下发与确认

编辑规则集后**不需要重新发布任何服务器的配置**：

1. 控制器为每台服务器计算它的**策略**：服务器的入站 / 出站绑定，加上这台服务器期望配置中各规则引用的规则集，以及这些规则集的内容。策略的哈希（SHA-256，规则集按 id 排序）就是“期望策略哈希”。
2. 每次同步回复带 `firewall: {hash, policy?}`。Agent 回报的哈希与期望一致时省略 `policy`。
3. Agent 先应用策略，再应用配置，然后在统计中回报 `firewall: {applied_hash, error?}`。`error` 说明最新策略为什么没有应用（无法解析）；没有这类错误时，说明当前策略中哪些规则集在这台 Agent 上无法使用（例如校验失败），这样的规则集在其层拒绝全部连接。Agent 最多回报 512 个字符，控制器接受最多 2048 字节，所以中文等多字节内容也不会让同步被拒绝。策略保存在 Agent 的状态库中，重启后在联系上控制器之前继续使用。
4. 规则集被编辑、服务器绑定被修改时，控制器唤醒使用它的服务器（`GET /agent/watch` 返回 `firewall_changed: true`），Agent 立即同步，不等轮询间隔。
5. 规则的绑定随配置一起发布，配置与策略在同一次同步中送达；Agent 在新配置生效前保留旧规则仍在使用的规则集。

`GET /nodes` 和 `GET /nodes/{id}/firewall` 的 `firewall` 显示每台服务器的状态：

| `state` | 含义 |
| --- | --- |
| `applied` | Agent 确认的哈希等于期望哈希 |
| `waiting` | Agent 在线且支持规则集，尚未确认最新策略（通常几秒内） |
| `offline` | 超过 30 秒没有同步；重新连接后确认 |
| `too_old` | Agent 从未回报支持规则集：请先升级 |
| `not_connected` | Agent 从未连接 |
| `unused` | 没有任何绑定，Agent 也不支持规则集：无需确认 |

同时返回 `desired_hash`、`applied_hash` 和 Agent 回报的 `error`。面板在“防火墙规则集 → 服务器策略”和服务器资料中显示期望哈希与已确认哈希的前 12 位，以及不一致的原因和 `error`。

同步不带 `stats.firewall` 时（Agent 被降级到旧版本，Agent 使用新的状态目录、还在第一次同步，或者 Agent 正在停止、发出最后一次同步），控制器清除这台服务器已确认的哈希：不执行规则集的 Agent 不会显示为 `applied`。新 Agent 启动后的第一次同步不带回报（它要先从回复中确认控制器支持规则集），所以 Agent 每次重启后会有一个轮询周期显示 `waiting`，下一次同步即恢复。

策略按服务器限制为 1 MiB（序列化后），超过时绑定或发布返回 400 `the rule sets used on server <名称> exceed 1024 KiB together; use fewer or smaller sets`。

## 删除

被任何服务器或规则使用的规则集不能删除：**409** `rule set <名称> is still bound: server <名称> (inbound), rule <规则> on server <名称>; remove these bindings first`。先在服务器或规则中解除绑定。

## 兼容性与旧 Agent

与 0.147.0 分方向限速、0.149.0 出口代理的做法相同：

- 控制器在每个同步回复中带 `firewall`。新 Agent 收到后在统计中回报 `stats.firewall`；控制器第一次收到时写入元数据 `firewall_node:<节点 id>`，此后这台服务器视为支持，删除服务器时一并删除。`GET /nodes` 的 `firewall_support` 显示该状态。
- 没有支持记录的服务器：
  - 为它新增服务器绑定（`PUT /nodes/{id}/firewall`）返回 **409**；
  - 任何发布路径（单节点发布、批量预览和发布、回滚、模板、共同规则、链路）给它带 `firewall_inbound_set` 的规则时返回 **409**。

  两种 409 的文字相同：`the agent on server <名称> is too old for firewall rule sets; upgrade it first`；从未连接过面板的服务器：`server <名称> has not connected to the panel yet; firewall rule sets need its agent to report in first`。检查在所有发布路径共用的一处（`topology::prepare`）进行，规则集不会在某台服务器上被静默丢弃。解除绑定（设为 `null`）不受限制。
- 旧 Agent 忽略同步回复中的 `firewall`，不使用规则集的配置照常运行。
- 新 Agent 对 0.149.0 及更早的控制器：旧控制器不发 `firewall`，新 Agent 不回报（旧控制器的 `EngineStats` 拒绝未知字段），并清除之前保存的策略，转发不受影响。
- 跨面板共享的规则由共享定义重新生成，不能绑定规则集（400 `rule <名称> belongs to share <名称>; a share's rules cannot have a firewall rule set`）。
- 已回报支持的 Agent 如果被降级，它的同步不再带回报：控制器清除已确认的哈希，状态显示 `waiting`（超过 30 秒未同步时为 `offline`），不会停在 `applied`。支持记录只写一次，所以绑定仍按支持处理。下面是在同一状态目录上原地换成真实 0.149.0 Agent 的实测结果（其他旧版本没有测试）：
  - **只有服务器绑定**（这台服务器的规则都没有 `firewall_inbound_set`）：旧 Agent 照常同步和转发，但忽略全部规则集，**原来被规则集拒绝的来源会被放行**。面板显示 `waiting`，不会显示已应用。这种情况不是失败关闭。
  - **有规则带 `firewall_inbound_set`**：新 Agent 保存在状态目录里的配置含这个字段，0.149.0 Agent 启动时读取保存的配置即退出（退出码 1，`invalid stored agent config: unknown field firewall_inbound_set`），这台服务器停止转发。只有这种情况是失败关闭。

  所以，在使用规则集的服务器上降级 Agent，结果要么是规则集不再执行，要么是服务器停止转发。下面两种退回做法也用真实 0.149.0 Agent 在同一状态目录上实测过（各连续运行两次，结果一致）：
  - **旧 Agent 启动失败后恢复**：在同一状态目录上装回新版 Agent（不需要重新注册）。它读取保存的配置照常运行，规则集重新生效，面板重新显示 `applied`。旧 Agent 的失败启动不会改动保存的配置。
  - **先解除规则级绑定再降级**：在面板中去掉这台服务器上所有规则的入站规则集并发布，等 `GET /nodes` 的 `applied_revision` 等于这次发布的版本，再换 0.149.0 Agent。它能启动，照常同步和转发。但服务器绑定仍在时，旧 Agent 忽略它，原来被拒绝的来源会被放行：这条路径只保证能退回，**不保留防火墙保护**。

  升级顺序：先控制器，后 Agent。

## 规则测试

`POST /api/v1/firewall/test`，面板“防火墙规则集”页底部的“规则测试”和列表中的“测试”按钮：

```json
{ "set_id": "fs-…", "source": "203.0.113.7" }
{ "node_id": "n-…", "rule_id": "r-…", "source": "203.0.113.7" }
{ "node_id": "n-…", "destination": "api.example.com", "port": 443, "address": "93.184.216.34" }
```

- 给 `set_id`：只测这个规则集；入站给 `source`，出站给 `destination` 和 `port`。
- 给 `node_id`（及可选的 `rule_id`）：按这台服务器的**期望策略**测试全部层；给 `rule_id` 时还包括规则入站层和规则自身的来源 / 目的地列表（`rule_lists`）。协议网关规则不能测试（400）。
- 出站目的地是域名时可以给 `address`（解析出的一个地址）；不给时只凭域名判断，必须看地址才能决定时该层结果为 `needs_address`。

返回：

```json
{
  "direction": "inbound",
  "decision": "deny",
  "policy_hash": "…",
  "layers": [
    { "layer": "server_inbound", "set_id": "fs-…", "set_name": "黑名单", "rule_index": 1, "default_action": false, "result": "deny" },
    { "layer": "rule_inbound", "set_id": "fs-…", "set_name": "Office only", "default_action": true, "result": "allow" },
    { "layer": "rule_lists", "default_action": false, "result": "allow" }
  ]
}
```

`rule_index` 从 0 开始（面板显示为“第 N 条规则”，从 1 开始）；`default_action: true` 表示默认动作决定；`result` 为 `allow`、`deny`、`needs_address` 或 `missing`（绑定的规则集不可用，拒绝）。`decision` 在任一层为 `deny` / `missing` 时是 `deny`，否则有 `needs_address` 时是 `needs_address`，否则 `allow`。`policy_hash` 与服务器的期望哈希相同；Agent 已确认这个哈希时，测试结果就是 Agent 的实际判定。

非系统管理员测试服务器时，系统规则集（以及调用者看不到的任何规则集）那一层只给出结果，不给出是哪个规则集、哪条规则：没有 `set_id`、`set_name`、`rule_index`，`default_action` 为 `false`，`detail` 为 `a rule set outside your tenant decides`（面板显示“由租户之外的规则集决定”）。`decision` 不变。

测试服务器绑定时只读取这台服务器的期望配置，不读取其他服务器的配置。

## 权限

- **系统规则集**只有系统管理员能读取规则内容、创建、修改和删除，也只有系统规则集能绑定到服务器。
- **服务器绑定**（`PUT /nodes/{id}/firewall`）只有系统管理员能修改（其他角色 403）。能看到服务器的用户可以读取它的状态。
- **租户管理员**可以创建、修改、删除本租户的租户规则集，并在规则编辑器中绑定到本租户的规则。规则只能绑定**它所属租户**的入站规则集；其他租户的规则集或不存在的规则集返回 404。
- 租户用户看不到其他租户的规则集，也看不到系统规则集的内容：读取、修改、删除、测试这些规则集都返回 **404**。测试自己的服务器时，系统规则集那一层只显示结果（见“规则测试”）。但租户能看到绑定在自己服务器上的系统规则集的**名称**：服务器状态（`GET /nodes` 的 `firewall`）列出入站和出站规则集的 ID 和名称，拦截记录的详情写出规则集名称和拒绝它的规则序号；规则本身（来源、目的地、端口）不公开。给系统规则集命名时不要写入不想让租户看到的信息。只读角色可以查看和测试，修改返回 403。
- API 令牌：读取和测试需要 `read`，修改规则集和绑定需要 `nodes:write`。

## 面板

- 侧栏“转发配置 → 防火墙规则集”：规则集列表（范围、方向、默认动作、规则数、使用位置），新建、编辑（规则用 ↑ / ↓ 调整顺序）、删除、测试；“服务器策略”表显示每台服务器的入站 / 出站规则集、规则绑定数、期望 / 已确认哈希和状态，系统管理员可以“绑定…”；页面底部是规则测试。
- 服务器资料（系统管理员）有“服务器防火墙规则集”一节，可选择入站和出站规则集，并显示当前状态；Agent 尚未回报支持时提示先升级。
- 规则编辑器“高级”区域有“入站防火墙规则集”，列出该规则租户的入站规则集；受管协议网关不显示。所选服务器的 Agent 尚未回报支持时提示发布会被拒绝。
- 拦截记录的原因显示为“防火墙规则集拒绝”，详情翻译为界面语言。控制器的 409 / 400 原因也翻译显示。

## 限制

| 项目 | 上限 |
| --- | --- |
| 规则集名称 | 1–120 个字符 |
| 每个规则集的规则 | 256 条 |
| 每条入站规则的来源 | 1–256 个 |
| 每条出站规则的目的地 / 端口 | 各 256 个 |
| 每个规则集 | 1 MiB（序列化后），创建和修改时检查：400 `a rule set is at most 1024 KiB; use fewer rules or entries` |
| 每台服务器的策略 | 1 MiB（序列化后） |
| 每个租户的规则集 | 64 个；系统规则集另计，最多 64 个。超过时新建返回 409 `at most 64 firewall rule sets per tenant; delete one first` / `at most 64 system firewall rule sets; delete one first` |
| Agent 回报的 `error` | 512 个字符（控制器接受最多 2048 字节） |

已知限制：

- 反向隧道的流量不受出站规则集约束（私有端的 Agent 直接连接目标，见上文“绑定位置”）。
- Agent 重启时只恢复最新收到的策略，不恢复为旧配置暂时保留的规则集。如果新配置一直应用失败、Agent 恢复运行旧配置，旧配置中引用了已从最新策略移除的规则集的规则，在新配置生效之前拒绝全部连接（缺失的规则集拒绝一切，不会放行）。
- 被规则集拒绝的 SOCKS5 BIND 对端不写拦截记录。

## 暂不支持

- GeoIP / ASN 匹配；
- 外部规则文件、订阅式规则列表；
- BitTorrent / QUIC 等协议识别过滤；
- 捕获或保存被拒绝连接的数据；
- 按套餐或用户自动套用的默认 / 必选规则集；
- 转发端点（端点组）和跨面板共享上的规则集；
- 订阅拉取的防火墙（订阅已有自己的来源允许列表，见 [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)）；
- 规则的出站规则集（只有服务器出站一层）；
- 协议网关客户端的规则集（由协议引擎检查）；
- 反向隧道私有端拨号的出站规则集。

## 与目的地 ACL 的差异修正

本版本修正了目的地 ACL 的后缀匹配：此前 `*.example.com` 会误匹配 `badexample.com`，现在只匹配以 `.example.com` 结尾的子域名。规则集与目的地 ACL 共用这段代码。这同样作用于**拒绝列表**：`deny_destinations` 里的 `*.example.com` 不再拦截 `badexample.com` 这样的相似域名；如果以前依赖这种误匹配拦截相似域名，需要为它们单独写条目。

## 测试

- `crates/relay-platform/src/firewall.rs` 单元测试：第一条匹配优先于后面更宽的规则；空规则集使用默认动作；IPv4 映射 IPv6 来源；端口范围两端；`*.后缀` 对裸域名和相似后缀；名称何时需要地址；多个地址逐个保留或拒绝；层的顺序与缺失 / 方向不符的规则集；Agent 在旧规则仍运行时保留已删除的规则集；方向不符的匹配条件；多字节错误信息按字符截断后总在控制器的上限内；无法使用的规则集拒绝并写入回报的 `error`；Agent 只凭名称的判定与测试一致。
- `crates/relay-platform/src/destination_acl.rs` 单元测试：含 NUL、空格或全角句点的名称不会只凭名称放行；含下划线的名称仍只凭名称判定。
- `crates/relay-platform/tests/firewall.rs`：真实控制器和 Agent 在回环地址上运行。
  - 服务器入站拒绝而规则入站允许，以及反过来，都被拒绝；没有服务器规则集时规则入站规则集仍然生效；
  - 规则信任所有 PROXY 发送方时，被服务器规则集拒绝的发送方声称允许的地址仍被拒绝，目标没有收到连接；报头中的地址同样被检查；
  - SOCKS5 BIND 中被服务器规则集拒绝的对端不被接受；
  - SOCKS5 UDP 关联中，被服务器规则集拒绝的主机抢先发送的第一个数据报被丢弃且得不到回复，关联仍属于合法客户端，并写入拦截记录；
  - 不是合法主机名的名称（含 NUL）不会原样交给出口代理，上游没有收到连接；
  - 不再回报的 Agent（降级）不再显示为 `applied`；
  - 每个租户最多 64 个规则集，超过 1 MiB 的规则集在创建和修改时被拒绝；
  - 编辑规则集无需发布即送达 Agent（Agent 轮询间隔 60 秒，只能靠唤醒），确认哈希随之更新；
  - 出站规则集在连接之前拒绝固定目标、SOCKS5 和 HTTP CONNECT 目的地，目标没有收到任何连接；
  - 出站规则集拒绝出口代理上游时换下一个上游，全部被拒绝时拒绝客户端，上游都没有收到连接；
  - 拦截记录的原因是 `firewall`；
  - 删除使用中的规则集返回 409；旧 Agent 的 409（服务器绑定和规则发布）；
  - 租户隔离（含规则测试不向租户透露系统规则集）；规则测试与 Agent 的实际行为一致（一个允许、一个拒绝）。
- `scripts/test_web_firewall.cjs`：规则集编辑器（顺序、上移下移、单个 IP 补全为 /32 和 /128、端口和数量校验、创建后方向固定）、删除前检查、规则编辑器的入站规则集（只列该租户的入站规则集、协议网关不带、旧 Agent 提示）、服务器绑定和状态、规则测试的请求与结果、页面的角色区别、拦截详情和拒绝原因的翻译，中英文各运行一次。

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

**出站覆盖范围**：固定目标（含预热连接、多路径、UDP 目标）、SOCKS5 / HTTP CONNECT / HTTP/2 CONNECT / Shadowsocks 客户端请求的目的地（含 Shadowsocks UDP、SOCKS5 UDP 和 BIND 对端），以及**出口代理的上游地址**。出口代理上游的选择：上游地址也是这台服务器发起的连接，所以同样受出站规则集约束；被拒绝的上游会被跳过，按顺序尝试下一个，全部被拒绝时拒绝客户端并记录拦截。目的地本身仍按上文检查。受管协议网关的目的地和 Reality 认证失败时的伪装回落都经本地桥连接，同样受出站规则集约束（以前已是如此）。反向隧道私有端连接目标之前也按出站规则集检查，见下文。

**协议网关**（VLESS / Reality / Trojan / VMess / AnyTLS / Hysteria2 / TUIC）：网关的公网端口由 Agent 自己监听，协议引擎只监听本机回环端口。Agent 收到连接（TCP）或数据报（Hysteria2、TUIC 的 UDP / QUIC）时，先按客户端**自己的地址**（内核给出的对端地址，IPv4 映射地址先转回 IPv4）依次检查规则到期、服务器入站、规则入站和规则自身的来源列表，通过后才把字节交给协议引擎：

- 被拒绝的 TCP 客户端在接受后立即被重置，Agent 不读取它发来的任何字节，协议引擎看不到这个连接，不会进行 TLS 握手，也不会触发 Reality 伪装回落；内核仍会完成 TCP 三次握手。
- UDP 的每个数据报都检查。被拒绝的数据报进入 Agent 进程后被丢弃，不会到达协议引擎，因此不会有 QUIC 握手或任何回复（比以前由协议引擎解密 QUIC 后再拒绝更省资源）。规则集修改后，已建立的 QUIC 关联在下一个数据报（客户端发来的或引擎发回的）时按新策略检查；被拒绝时客户端收不到引擎之后的数据报，关联结束。客户端地址或端口变化（NAT 重绑定、迁移）相当于新的关联，重新检查；旧关联空闲后过期。关联建立 5 秒后结束（不论客户端还在发什么），除非客户端证明它收得到引擎的回包：协议引擎在任何认证之前就会回应合法的 QUIC Initial（固定版本的 sing-box 实测如此），而任何人都能构造 Initial，也能从收不到回包的（伪造的）地址发。证明方式是客户端的数据报发往引擎第一个 QUIC 回包所选的连接 ID（之后的每个 QUIC 包都如此）；Hysteria2 开了混淆时报头不可读，回包之后客户端再发任何数据报即算（能得到回包本身就需要混淆密码）。证明之后才按空闲时间过期（至少 31 秒）。
- 拒绝写入拦截记录（协议 `gateway`，来源是客户端自己的地址），与普通规则相同。
- 识别不了伪造源地址的 UDP 数据报（任何 UDP 服务都如此）；本机进程可以直接连接协议引擎的回环端口，这与网关本地桥（也在回环地址上）的信任边界相同。
- 已建立的 TCP 连接与普通规则一样只在建立时检查。
- 资源上界（不是用户可见的限额）：每个网关最多 4096 个客户端 TCP 连接和 4096 个 UDP 关联（`max_connections`、`udp_max_sessions` 更大时取它们）；每个来源（IPv4 地址或 IPv6 /64）最多 256 个连接和 64 个关联（持有更大 IPv6 前缀的客户端，例如一个 /56 含 256 个 /64，算作多个来源，此时靠每个网关的总上界约束）；所有网关合计最多占用 Agent 打开文件上限的一半。超出时拒绝并写入 `connection_limit` 或 `udp_session_limit` 拦截记录。一方结束自己的方向后，另一方向超过 `idle_timeout_secs` 没有数据就关闭；客户端连接开启 TCP keepalive。

需要较新的 Agent（回报 `covers` 含 `gateway_inbound`，见下文“旧 Agent”）。

**反向隧道**（[REVERSE_TUNNELS.md](REVERSE_TUNNELS.md)）：私有端的 Agent 先在本机解析隧道目标，按私有服务器的出站规则集逐个判定解析出的地址（方式与上文“出站：域名与多个地址”相同），只连接允许的地址，TCP 和 UDP 都如此；全部被拒绝时不连接，并告诉公网端原因，公网端为这个客户端写拦截记录，详情以 `reverse tunnel private server: ` 开头。公网端的入站层照常检查。需要较新的 Agent（`covers` 含 `reverse_private_outbound`）。

不在范围内：Agent 自己的连接（与控制器同步、WireGuard、目标健康探测）不受规则集约束，与目的地 ACL 相同；这不是整机防火墙，只约束经 Relay 规则、网关和隧道的业务流量。

**旧 Agent**：0.150.0 的 Agent 在自己的规则上执行规则集，但不检查协议网关的客户端，也不检查反向隧道私有端的拨号。Agent 在回报中用 `covers` 说明它还覆盖哪些路径，控制器记在 `firewall_node:<id>` 中，并随 Agent 每次回报更新：降级到 0.150.0 的 Agent 下一次回报时失去它；降级到 0.149.0 及更早的 Agent 不再回报，`covers` 和支持标记一样保留（一次写入的标记），服务器状态因此不会显示 `uncovered`，而那些 Agent 根本不执行规则集——不要在使用规则集的服务器上降级 Agent。没有相应覆盖时：

- 给有协议网关的服务器绑定服务器入站规则集、给网关规则绑定入站规则集、在已绑定服务器入站规则集的服务器上新增网关，以及对网关规则做规则测试，返回 409 `the agent on server {name} does not apply firewall rule sets to protocol gateways; upgrade it first`；
- 给是反向隧道私有端的服务器绑定出站规则集，以及在已绑定出站规则集的私有服务器上新建、启用隧道或修改隧道的私有服务器、目标、协议，返回 409 `the agent on server {name} does not apply its outbound firewall rule set to reverse tunnels; upgrade it first`；
- 控制器升级前已经存在的组合照常下发、继续运行，不会突然中断；服务器状态的 `uncovered` 列出没有被规则集约束的路径（`gateways`、`reverse_tunnels`），面板显示为警告。升级 Agent 后自动消失。

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
- 给 `node_id`（及可选的 `rule_id`）：按这台服务器的**期望策略**测试全部层；给 `rule_id` 时还包括规则入站层和规则自身的来源 / 目的地列表（`rule_lists`）。协议网关规则只有在 Agent 覆盖网关时才能测试（否则 409，见“旧 Agent”）。
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
- 规则编辑器“高级”区域有“入站防火墙规则集”，列出该规则租户的入站规则集；受管协议网关也可以选择，并说明它在协议握手之前按客户端地址检查、需要较新的 Agent。所选服务器的 Agent 尚未回报支持时提示发布会被拒绝。
- 服务器状态有 `uncovered` 时，在状态下方显示哪些路径不受规则集约束、需要升级 Agent。
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

- 协议网关只在 Agent 收到连接时检查来源；TCP 三次握手由内核完成，伪造源地址的 UDP 数据报无法识别，本机进程可以直接连接协议引擎的回环端口（见“绑定位置”）。
- 连接页显示的网关会话是本地桥上的会话，来源是回环地址；这类会话不能在面板上终止：终止也只会断开那一条代理连接，不会断开客户端外层的 TLS / QUIC 连接，客户端可以再开新的连接。网关客户端是否被拦截以 Agent 公网端口的判定为准，见拦截记录。
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
- 按内核层（nftables 等）过滤：规则集只在 Relay 的业务端口上执行。

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
  - 协议网关（Agent 的旧版本门控）：没有 `gateway_inbound` 的 Agent 上，服务器入站绑定、网关规则的规则集和规则测试返回 409；覆盖后通过，规则测试给出网关的判定；降级后已有网关保留、`uncovered` 为 `gateways`，新增网关返回 409。
- `crates/relay-platform/tests/reverse_tunnels.rs`：
  - 真实 Agent：私有端按出站规则集拒绝隧道目标（按名称和按解析出的地址，TCP 和 UDP），目标没有收到任何连接或数据报；公网端为客户端写拦截记录；编辑规则集无需发布即生效；
  - 控制器：没有 `reverse_private_outbound` 的私有服务器上，新建、启用和改目标返回 409；降级后已有隧道照常下发，`uncovered` 为 `reverse_tunnels`。
- `crates/relay-platform/tests/managed_gateways.rs`：
  - 用固定版本的 sing-box（需要 `RELAY_TEST_PROTOCOL_ENGINE`）：VLESS + Reality 和 Hysteria2 网关监听 `[::]`（TUIC、AnyTLS、Trojan、VMess 另有一项：被拒绝的来源收不到 TLS 握手的任何字节或 QUIC 回复，并写入拦截记录），被服务器入站规则集拒绝的来源（IPv4 映射和 IPv6）连不进去，目标没有收到连接；被拒绝的来源没有触发 Reality 伪装握手（伪装站点没有收到连接），也得不到 QUIC 版本协商回复（任何 QUIC 服务端都会回复）；拦截记录写客户端地址；规则集编辑后不重启协议引擎即生效，已建立的 QUIC 连接立即被切断而 TCP 连接保留；规则入站规则集；协议引擎换端口重启后旧连接结束、新连接到新端口。Reality 回落经本地桥计量，出站规则集拒绝伪装站点时回落失败并写拦截记录。`max_connections` 只按桥上的连接计一次；`udp_max_sessions` 为 1 时三个 Hysteria2 客户端仍能同时连上。
  - 用替身引擎（不需要 sing-box，默认运行）：协议引擎没有报出（或报出不可用的、或在启动行之后才报出）端口时配置不生效，公网端口不打开；新配置的引擎启动失败或超时时恢复上一代；`[::]` 网关按 IPv4 地址判定和记录 IPv4 映射来源，IPv6 来源照常；TCP 双向半关闭照传，一方结束后另一方安静超过空闲时间时名额释放，打开的连接没有空闲限制；每个来源 256 个连接的上界；规则的 `udp_max_sessions` 为 1 时多个客户端仍能各自建立关联（这个值仍只计桥上的 UDP 会话），关联数达到 4096 时下一个客户端被拒绝并写入 `udp_session_limit` 拦截记录，已有关联不受影响；每个来源 64 个关联的上界；引擎未回应的关联 5 秒后结束；空闲过期和 NAT 重绑定后旧关联回收；策略修改后引擎发回的下一个数据报不再送达被拒客户端；引擎重启换端口后旧关联和旧连接结束，即使旧端口仍开着；新关联同时到达的两个数据报都送达引擎；客户端发往引擎所选连接 ID（或混淆网关回包之后的任何数据报）才让关联长存，只重发首个数据报不算；客户端连接开启 keepalive；客户端先结束自己方向的半关闭；运行中调低打开文件上限后按新上限计；网关在 `0.0.0.0` 和 `[::]` 之间迁移（旧监听上还有数百个关联）、同一次发布把 `[::]` 网关的端口交给 IPv4 普通规则都能成功；迁到 `[::]` 时引擎启动失败或配置无法落盘，IPv4 监听恢复、修订不变；普通规则自己的 `[::]` 只收 IPv6，迁移绑定失败时原 IPv4 监听和 UDP 会话不受影响；活动端口上的规则改成网关或改回都须先停用并等服务器应用（控制器发布时返回 409，见 `tests/firewall.rs`）；引擎持续发回包时，繁忙的关联按预算把线程让给 Agent 的其他任务，单线程运行时上客户端的包仍按时送到引擎（这一项只在空闲的多核机器上能可靠抓到回退，4 核以下或有负载时只是弱保护）；在单独进程里调低打开文件上限后，所有网关合计只占一半，其余部分仍能打开连接。
- `crates/relay-platform/src/engine/gateway_front.rs` 的单元测试：内核不能拆分合并发送的数据报时改为逐个发送；控制信息被截断时按一个数据报丢弃，不报错也不结束关联。
- `scripts/test_web_firewall.cjs`：规则集编辑器（顺序、上移下移、单个 IP 补全为 /32 和 /128、端口和数量校验、创建后方向固定）、删除前检查、规则编辑器的入站规则集（只列该租户的入站规则集、协议网关保留规则集并显示说明、旧 Agent 提示）、服务器绑定和状态（含 `uncovered` 警告）、规则测试的请求与结果（网关规则也可选）、页面的角色区别、拦截详情（含反向隧道私有端前缀）和拒绝原因（含两条 409）的翻译，中英文各运行一次。

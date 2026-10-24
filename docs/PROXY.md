# PROXY protocol 与原始连接地址

0.7.0 为 TCP 实现 PROXY v1/v2，为 UDP 实现逐包 PROXY v2。入口解析、逐目标输出、原始来源 ACL/哈希、TLS 顺序、应用负载计量均使用同一配置模型。协议依据 [HAProxy 公布的格式](https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt)，没有引入商业产品代码。

此功能传递连接元数据；它不提供 SOCKS/HTTP 代理、透明源地址绑定、跨节点拓扑或用户身份认证。目标服务看到的套接字对端仍是转发节点，必须解析 PROXY 报头才能获得声明的原始地址。

## 配置

入口规则可设置：

```json
"inbound_proxy": {
  "version": "v2",
  "trusted_sources": ["192.0.2.10/32", "2001:db8:1::10/128"],
  "placement": "before_tls",
  "max_header_bytes": 4096
}
```

| 字段 | 含义 |
| --- | --- |
| `version` | 必填；TCP 支持 `v1`、`v2`、`any`，UDP 和 `both` 必须为 `v2` |
| `trusted_sources` | 必填，1..256 个 CIDR；匹配实际连接对端，不匹配报头中的来源 |
| `placement` | 默认 `before_tls`；`inside_tls` 要求入口配置 TLS |
| `max_header_bytes` | 默认 4096；允许 16..65551，包含固定报头、地址和 TLV。v1 另外受 107 字节上限约束 |

未设置 `inbound_proxy` 时不识别也不剥离 PROXY 报头。启用后，每条 TCP 连接或每个 UDP 包都必须提供对应报头；`any` 只允许两种格式，不允许省略报头。不可信实际对端先被拒绝，只有解析成功后才用声明的来源执行 `allow_sources`、`deny_sources` 和 `source_hash`。IPv4 映射 IPv6 地址在 ACL/哈希中按 IPv4 处理，因此相应可信来源应填写 IPv4 CIDR。

每个目标可设置：

```json
"proxy_protocol": {
  "version": "v2",
  "placement": "before_tls",
  "checksum": true
}
```

`version` 必填；TCP 可选 v1/v2，UDP 和 `both` 必须为 v2。`checksum` 默认关闭，只允许 v2，开启后生成 CRC32C TLV。`placement` 默认 `before_tls`；`inside_tls` 要求该目标启用 TLS。未知字段与不支持的组合会在配置发布时被拒绝。

入口没有 PROXY 时，输出使用实际来源及实际接收目的地址；入口有合法地址报头时，保留声明的原始地址。报头中的目的地址仅作为元数据传递，不改变目标选择、目的端口映射或回复路由。输入 TLV 不向下一跳透传，输出 CRC32C 根据新报头重新生成。

## TCP 与 TLS

- TCP 报头只在连接开始时发送一次，后续应用数据保持原样，支持二进制和半关闭。
- `before_tls` 顺序为 PROXY → TLS → 应用数据；报头本身位于 TLS 之外。未启用 TLS 时顺序为 PROXY → 应用数据。
- `inside_tls` 顺序为 TLS → 加密通道内的 PROXY → 应用数据；两端必须明确约定此顺序。它不改变 TLS 的服务器名、CA 或 mTLS 客户端证书检查。
- 入口的报头读取和 TLS 握手共用一次 `connect_timeout_ms` 截止时间，并占用规则连接名额。出口解析 DNS、连接、报头写入和 TLS 握手共用出口连接截止时间。
- 报头缺失、格式错误、长度越界、TLS 顺序不一致或证书失败会关闭该连接，不会把未验证字节当成应用数据转发。
- 改动入口 PROXY 策略、出口策略集合，或同一目标的 PROXY 策略，会终止旧会话。仅增加无 PROXY 的普通目标仍遵守既有目标更新语义。

PROXY 与 CRC32C 都不证明客户端身份。入口的可信对端范围和 TLS/mTLS 配置承担不同职责；在 TLS 之前发送的报头不受 TLS 内容加密保护。

## UDP

每个请求数据包都单独携带一个 v2 报头，处理后剥离。出口配置 PROXY 时，每个请求包重新加头；回复为普通 UDP 应用负载，不加 PROXY 报头。空应用数据包也保留其数据包边界。

会话键同时包含实际对端、实际接收地址和声明的原始来源/目的地址。一个代理承载多个客户端不会复用为同一目标会话；两个代理提交相同声明也不会相互接收回复。每个包都重新执行对端信任、报头解析和来源 ACL。

回复发送至实际对端，并使用实际接收地址作为源 IP，不使用报头声明的来源作为回复目的地。监听具体 IP 直接使用该地址；通配监听通过内核 packet-info 获取实际目的地址。该路径当前实现于 Linux/macOS，macOS IPv4/IPv6 已有真实套接字测试，Linux 尚待实机验证。其他系统会在准备通配 UDP 监听时明确报错，可改为绑定具体 IP；不能假定通配地址就是实际目的地址。

IPv4 出口的 PROXY 报头加应用负载不得超过 65507 字节，IPv6 不得超过 65527 字节；超过时整包拒绝并不计费。操作系统实际允许的发送长度仍可能更小，接纳后发送失败遵守既有计量合同。不做应用层拆包，也不实现 IPv6 巨型数据包。

## 格式与计量边界

- v1 按规范校验空格、地址族、十进制端口及 CRLF，总长度最多 107 字节。分片读取不吞掉紧随其后的 TLS 或应用字节。
- v2 校验固定签名、版本、命令、长度、地址族和 TCP/UDP 类型；在读取可变正文前检查配置的长度上限。
- 已支持的地址正文后，TLV 必须有完整长度。CRC32C TLV 必须恰为 4 字节且只出现一次，存在时校验；其余 TLV 忽略，不作为认证或 TLS 验证结果。
- v1 `UNKNOWN`、v2 `LOCAL`/`UNSPEC` 使用实际连接地址。按协议语义，`LOCAL` 与 `UNSPEC` 的正文被忽略，不承诺校验其内部 CRC/TLV。有效 Unix 地址正文使用实际 IP 地址回退，不表示支持 Unix 域监听。
- PROXY 报头不进入应用计量、流量配额、共享预算或速率桶。记录的仍是已接纳的上下行应用负载，可能包含随后未能写出的数据。

## 运行与验证

[proxy-hop.json](../examples/proxy-hop.json) 在同一独立进程中构造两个 TCP/UDP 规则：19001 普通入口 → 携带 v2+CRC32C 的 19002 → 19000 回显服务。所有监听限定本机。

```sh
python3 scripts/echo_fixture.py --port 19000
./target/release/relay validate --config examples/proxy-hop.json
./target/release/relay standalone --config examples/proxy-hop.json --database ./state/proxy/agent.sqlite
python3 scripts/probe.py --host 127.0.0.1 --port 19001
```

分别在终端启动常驻服务。两条规则各记录自身上下行应用负载；同一业务流经过两个规则会产生两条计量记录，这是按规则计量，不是报头计费。

Rust 自动化覆盖格式、分片、CRC、TLS/mTLS 顺序、真实对端信任、来源 ACL/哈希、配置变更、UDP 复用与回复源地址，以及 HTTP 发布到真实 Agent 的链路。外部互通脚本接受现有 HAProxy 路径，不安装系统服务：

```sh
python3 scripts/check_proxy_interop.py --haproxy /path/to/haproxy --output artifacts/proxy-interop.json
```

链路为 Python 客户端 → HAProxy → Relay → HAProxy → Python 观察端。入口与出口各使用 v1、v2、v2+CRC，结合 IPv4/IPv6 原始地址共 18 种情况；观察端独立解析地址并计算 CRC，核对二进制回显、半关闭及账本。该脚本仅验证本机明文 TCP 互通；TLS 与 UDP 的外部实现互通、广域网和压力测试另行验收。

## 升级

SQLite schema v4、恢复日志与账本格式不变，未设置新字段的旧配置保持兼容。0.6 Agent 会拒绝未知新字段，应先升级节点再发布 PROXY 配置。所有节点支持的功能以能力目录及实际 `applied_revision`/`apply_error` 为准，控制面接受配置不代表远端已经应用。

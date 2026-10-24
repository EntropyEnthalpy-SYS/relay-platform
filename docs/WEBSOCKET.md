# WS / WSS 流隧道与 relay-stream-v1

0.8.0 在既有 TCP 转发流中接入 WebSocket，入口与各目标可分别启用；同时配置该方向的 TLS 即为 WSS。管理 API、Agent、standalone 和规则表单使用相同字段。这里的应用协议是本项目公开定义的 `relay-stream-v1`，不是任意二进制 WebSocket 服务，也没有宣称兼容参考产品的私有隧道。

## 字段

入口：

```json
"inbound_websocket": {
  "path": "/relay?version=1",
  "host": "relay.example.com:443",
  "allowed_origins": ["https://console.example.com"]
}
```

每个目标：

```json
{
  "address": "192.0.2.10:443",
  "weight": 1,
  "tls": {"server_name": "relay.example.com", "ca": "private-root", "identity": "client-v1"},
  "websocket": {
    "path": "/relay?version=1",
    "host": "relay.example.com:443",
    "origin": "https://console.example.com"
  }
}
```

- `path` 必填，最多 1024 个 ASCII 字节，必须以一个 `/` 开始，不允许片段、空白或反斜杠。整个路径及查询字符串精确比较，不解码或重写。
- 出口 `host` 必填；入口 `host` 可省略，省略只取消指定主机的匹配检查，仍要求有效且唯一的 HTTP Host。最多 255 个 ASCII 字节，可以含数字端口和括号 IPv6；端口不得超过 65535。配置了入口 Host 时忽略大小写比较，端口按文本匹配，不推断默认端口。
- `allowed_origins` 默认为空，最多 64 个互不重复的规范 HTTP(S) Origin，例如 `https://console.example.com`；不接受通配符、`null`、路径、尾部斜杠或非规范默认端口。请求没有 Origin 时允许通过，以支持节点程序；请求带 Origin 时必须精确匹配允许列表。出口 `origin` 可省略。Origin 和 Host 检查不是身份认证，公网入口应结合 ACL 与 mTLS。
- HTTP Host、实际拨号地址与 TLS `server_name` 各有用途；拨号、DNS 缓存和出口绑定仍由统一转发引擎执行。不会根据 HTTP Host 改换拨号地址，也不信任 `X-Forwarded-For`。
- 未设置 WebSocket 字段时保持普通流。任何 WS 配置都要求规则 `protocol:"tcp"`，UDP 和双协议组合拒绝。一条规则可明确配置 WS 与普通流目标；每个目标只使用其声明的传输，不因该目标升级失败而按普通流重试。既有规则禁止混用明文和 TLS 出口的约束继续有效。

## 线路协议

使用 [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) 的 HTTP/1.1 Upgrade 和帧格式。客户端必须请求 `Sec-WebSocket-Protocol: relay-stream-v1`，服务端必须选择同一子协议。收到 101 之前不得发送帧。标准掩码、分片、Ping/Pong 和关闭帧交由 Tungstenite 校验；不协商压缩及其他扩展，出口拒绝未经请求的扩展响应。

每条连接承载一个双向字节流，每条**完整二进制消息**为一条记录：

| 第一字节 | 后续字节 | 语义 |
| --- | --- | --- |
| `00` | 1..65536 字节 | DATA：本方向应用负载 |
| `01` | 无 | FIN：本方向应用流结束，另一个方向仍可继续 |

空消息、零长度 DATA、额外 FIN 内容、未知类型、文本消息、重复 FIN 和 FIN 之后的 DATA 都会导致连接失败。每帧及完整消息最多 65537 字节，分片也不能绕过消息上限。此版本不承载 UDP，不做连接复用、重连续传、多路径或复制。

两端各发一次 FIN，且处理完先前 DATA 后，开始 WebSocket 关闭握手。无状态码或 1000 表示正常关闭；提前 Close、错误状态码、直接 TCP 断开都不是完整流结束。不得用 WebSocket Close 代替单向 FIN，否则会丢失另一方向仍需返回的数据。关闭握手受规则 `connect_timeout_ms` 限制；控制帧被阻塞时的刷出也使用此超时。额度耗尽、计量故障和撤销配置会失败关闭，不伪装成正常双向结束。

## 与 TLS、PROXY 和计量的关系

每个方向固定按以下顺序处理，未启用的层跳过：

```text
TCP 套接字
  → PROXY placement=before_tls
  → TLS / mTLS
  → PROXY placement=inside_tls
  → HTTP Upgrade / WebSocket
  → relay-stream-v1 记录
  → 应用字节流、统一限速与持久化计量
```

`inside_tls` 的 PROXY 报头在加密流内部、HTTP 升级之前，不在 WebSocket DATA 内部。标准 WebSocket 服务通常不接受这个前置报头，必须两端明确匹配。独立 Python WebSocket 互通不包含该组合；本项目原生节点的 WS/WSS 与 PROXY 两种位置另有集成测试。

TLS 继续校验 CA、服务器名和可选客户端证书，支持 TLS 1.2/1.3；WSS 仅声明 `http/1.1` ALPN。证书通过节点本地编号加载，不在 API 内上传私钥。TCP 建连、PROXY、TLS 和 HTTP 升级共用既有连接截止时间，不逐层重新增加超时时间。最大 HTTP 报头为 16 KiB。

持久化账本与限速只处理解包后的应用字节；HTTP、WS 帧、记录类型、FIN、Ping/Pong、TLS 和 PROXY 开销不计入当前额度。计量口径仍为先接纳再写入，后续写入失败可能已经扣量。运行统计在应用写入及刷出成功后增加，也不代表远端应用已确认。Ping/Pong 不延长应用空闲超时。

每连接使用一个帧处理任务，输入和输出队列各容量为 1，并允许一个等待刷出的确认。输入还可能有一个正在等待入队的消息及库内帧缓冲；不声称总内存只有一个 64 KiB 缓冲。输出 `flush` 等待实际传输刷出，慢端会反压，丢弃流会终止后台任务和连接。单条大消息受上述上限约束，不无限收集消息。

## 发布与示例

入口或逐目标 WS 安全参数变化会撤销原会话，包括把同一参数移动到另一个既有目标的情况。只增加普通目标等一般路由变更仍按既有约定保留旧连接。非法配置、证书错误或新监听准备失败时保留旧版本；下发后查看期望修订、实际修订及 `apply_error`。

SQLite schema v4、账本口径和恢复日志格式不变。0.7 Agent 会拒绝新字段，先升级控制器和节点，再发布 WS/WSS 配置。

本机两跳示例为 [websocket-hop.json](../examples/websocket-hop.json)：普通 TCP 客户端 → TCP/WS 入口 → WS/TCP 出口 → 回显目标。Host `relay.local` 仅用于升级请求匹配，不需要配置系统 DNS。

```sh
python3 scripts/echo_fixture.py --port 19000
# 另一个终端
./target/release/relay validate --config examples/websocket-hop.json
./target/release/relay standalone --config examples/websocket-hop.json \
  --database ./state/websocket/agent.sqlite
```

它只支持 TCP，不能使用默认同时发送 TCP/UDP 的 `scripts/probe.py` 来验收。可用 Python 标准 socket 连接 19001，发送字节并 `shutdown(SHUT_WR)`，继续读取直到 EOF；响应应与请求一致。两条规则各计入一份上下行应用量。

独立实现互通使用 [Python websockets](https://websockets.readthedocs.io/en/stable/reference/asyncio/client.html) 的客户端与服务端，依赖仅安装到单独测试环境：

```sh
python3 -m venv work/ws-interop
work/ws-interop/bin/python -m pip install -r scripts/requirements-interop.txt
work/ws-interop/bin/python scripts/check_websocket_interop.py \
  --binary target/release/relay --output artifacts/websocket-interop.json
```

脚本生成短期私有 CA 与证书，依次验证 WS、WSS、双向证书 WSS，检查双方关闭、反向响应、Host/路径/Origin/子协议和拒绝用例；所有套接字均为本机临时监听。证据及未验收边界见 [VALIDATION.md](VALIDATION.md)。浏览器点击、真实 Linux/WAN、生产证书续期与大规模连接压力仍需单独验收。

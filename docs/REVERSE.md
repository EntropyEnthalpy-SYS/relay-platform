# 反向 TCP 隧道：会话池与单连接多路复用

0.53.0 增加最小反向 TCP 隧道，0.57.0 增加会话池并发，0.82.0 增加独立的单连接多路复用协议。旧 `reverse-server`/`reverse-client` 仍是一条控制连接承载一个公网连接；新 `reverse-mux-server`/`reverse-mux-client` 在一条控制连接上用长度前缀帧复用多个公网连接。两者都不是 WireGuard。

## 使用

公共节点：

```bash
printf '%s\n' 'long-random-token' > /etc/relay/reverse.token
chmod 600 /etc/relay/reverse.token
relay reverse-server \
  --control-listen 0.0.0.0:19000 \
  --public-listen 0.0.0.0:19001 \
  --token-file /etc/relay/reverse.token
```

私有节点：

```bash
relay reverse-client \
  --server PUBLIC:19000 \
  --target 127.0.0.1:8080 \
  --token-file /etc/relay/reverse.token
```

公网客户端连接 `PUBLIC:19001`，流量由私有节点拨号到 `--target`。

单连接多路复用：

```bash
relay reverse-mux-server \
  --control-listen 0.0.0.0:19010 \
  --public-listen 0.0.0.0:19011 \
  --token-file /etc/relay/reverse.token \
  --max-streams 256 \
  --idle-timeout-secs 300 \
  --allow-public-cidr 203.0.113.0/24 \
  --max-controls 1024 \
  --max-total-streams 4096 \
  --max-stream-bytes 0 \
  --udp-listen 0.0.0.0:19011 \
  --udp-idle-secs 60 \
  --udp-queue 1024 \
  --udp-rate-pps 0 \
  --public-tls-cert server.pem --public-tls-key server-key.pem \
  --public-tls-client-ca client-ca.pem

relay reverse-mux-client \
  --server PUBLIC:19010 \
  --target 127.0.0.1:8080 \
  --token-file /etc/relay/reverse.token
```

控制连接可选 TLS（公网监听仍为明文，TLS 只保护控制连接及其中的复用负载）：

```bash
relay reverse-mux-server ... --tls-cert cert.pem --tls-key key.pem
relay reverse-mux-client ... --tls-ca ca.pem --tls-server-name relay.example
```

服务端加 `--tls-client-ca ca.pem`，客户端同时提供 `--tls-client-cert client.pem --tls-client-key client-key.pem` 即为双向 TLS。公网监听可另加 `--public-tls-cert/--public-tls-key`，让公网客户端直接使用 TLS；再加 `--public-tls-client-ca` 可要求公网客户端证书（mTLS）。

## 协议与边界

- 控制连接首行：`REVERSE <token>`；成功 `READY`，失败 `DENY`。
- 每次公网连接：服务器发 `OPEN`；客户端拨号目标，成功 `OK`，失败 `FAIL <error>`；随后原始 TCP 双向桥接。
- 控制连接必须在 10 秒内完成首行认证，否则关闭；目标拨号最多等待 5 秒，超时回 `FAIL`。
- 控制行最长 512 字节，token 1..256 字节；每条控制连接只服务一个公网连接。token 使用长度检查加逐字节异或累积比较，避免提前返回的明显时序差异。
- 客户端 `--sessions 1..64` 启动多个独立控制会话，服务端为每个已认证控制连接派生会话任务，因此可并发服务多个公网连接；并发度受会话数限制，不是单连接多路复用。
- 客户端在会话结束/失败后 250ms 重连；服务器持续接受新的已认证控制连接。
- 旧行协议没有单连接多路复用、流量计量、ACL、TLS、重放保护或流量填充；控制/公网端口应置于受信网络或外部 TLS 隧道后。mux 协议提供 TLS/mTLS 与公网 CIDR，但同样没有重放保护或流量填充。
- 多路复用握手：`REVERSE-MUX <token>`；token 同样使用常量时间比较；控制连接可用 TLS 或 mTLS，服务端证书/私钥必须同时提供，客户端用 CA 和服务器名校验；公网监听默认明文，提供 `--public-tls-cert/--public-tls-key` 后由服务端终止公网 TLS。随后 9 字节帧头（kind、u32 id、u32 长度）+ 负载，kind 为 `OPEN/OK/FAIL/DATA/FIN/RESET`；帧负载上限 64 KiB。
- 服务端为每个公网连接分配 id 并发 `OPEN`，客户端拨号目标后回 `OK`，再按 id 双向转发；一条控制连接可并发承载多个公网连接。
- `--max-controls 1..65535` 限制单进程已建立控制连接总数，默认 1024；达到上限后新认证返回 `DENY`，不同于每控制公网流上限。
- `--max-total-streams 1..1000000` 限制单进程所有控制的公网流总数，默认 4096；达到上限后新公网连接在 OPEN 前关闭。
- `--max-stream-bytes` 限制单条流的双向累计字节数，默认 0（不限）；达到上限后该流被重置，不影响邻居流。
- `--udp-listen` 启用公网 UDP 中继；需要同时设置 `--max-controls 1`。客户端用 `--udp-target` 指定固定 UDP 目标，或用 `--udp-socks5` 让公网数据报携带 SOCKS5 UDP 目标头（多目标模式）；两者互斥。
- `--udp-idle-secs` 设置 UDP association 空闲回收时间，默认 60 秒，范围 1..86400。
- `--udp-queue` 设置 UDP 接收队列长度，默认 1024，范围 16..65536。
- `--udp-rate-pps` 设置每 association 双向包速率，默认 0（不限）；超速丢包并计数。每个公网源地址形成一条 UDP association，空闲 60 秒回收；UDP 不走 TLS，公网端口应置于可信网络或外部加密隧道后。
- 认证首行有 10 秒超时，目标拨号有 5 秒超时；服务端每条控制连接默认最多 256 个并发公网流，`--max-streams 1..1024` 可调；超过上限的新公网连接立即关闭，不分配 id。
- 公网流默认 300 秒无数据即被关闭并发送 `RESET`；`--idle-timeout-secs 1..86400` 可调。
- 客户端 `reverse-mux-client` 在控制连接断开后 250ms 重连；mux 不提供重放保护、流量填充或按连接目标 ACL。
- mux 公网/控制半关闭会保留另一方向直到双方完成。控制握手（明文 token 或 TLS/mTLS）在独立任务中执行，不阻塞 accept；公网 TLS 握手同样在独立任务中执行并限制每控制 64 个待处理握手，均有 10 秒超时。
- `reverse-mux-server --metrics-listen 127.0.0.1:9100` 提供本进程的 Prometheus 指标；控制器 `/metrics` 的 `relay_reverse_mux_process_available` 为 0 表示 mux 不在该进程，不能把零当作隧道空闲。
- 测试覆盖错误 token、单控制连接上两个并发公网连接、双目标回显、流上限校验和 idle 超时校验；旧测试覆盖顺序连接和 session pool。未做真实公网、NAT、长时或高并发验收。

## 0.103.0 UDP over the mux

- A public UDP source creates an association; the server sends `OPEN` with the
  `udp-v1` feature and then `DATAGRAM` (kind 8) frames.
- The client opens a fixed UDP target from `--udp-target`; target replies return
  as `DATAGRAM` frames and are written back to the public source.
- SOCKS5 UDP mode is stateless per datagram and uses the client's unconnected UDP socket; multiple destinations share one association. The target address is resolved by the client.
- UDP associations count against `--max-streams` and `--max-total-streams`;
  `--max-stream-bytes` counts both directions. There is no credit window for
  datagrams; a full 1024-entry receive queue drops new datagrams.
- The server requires `--max-controls 1` while UDP is enabled because the
  public UDP socket has no control-affinity field. UDP is not encrypted by the
  mux; use an external encrypted tunnel if the public network is untrusted.

## 0.97.0 stream isolation and flow control

- New peers negotiate `flow-control-v1` in the OPEN and OK payloads. Both directions start with 32 DATA-frame credits. WINDOW (kind 7) carries a four-byte big-endian credit count; one credit is returned only after a complete DATA payload has been written to its destination socket. A sender waits for its own credits outside the shared control reader. FIN preserves the other direction until it also finishes.
- Each inbound stream queue remains bounded at 32 frames (at most 2 MiB for maximum-size 64 KiB frames; normal DATA writes are 16 KiB). The control reader never waits for queue space. Saturated legacy or nonconforming streams are reset individually after one cooperative yield. Upgrade both ends for credit-based backpressure; older peers remain supported through the original six-frame exchange without the new flow-control guarantee.
- Blocked public socket writes are cancellable and bounded by the configured idle timeout. Blocked client target writes have a 30-second stall deadline. Connection loss cancels all child streams; stream resets cancel only that stream. A control frame has a 5-second write/lock deadline; any abandoned partial frame closes the entire control connection to prevent framing corruption.
- `--max-controls` bounds established controls per server process (default 1024, range 1..65535); a denied control receives `DENY`. It is separate from the 64 pending authentications and per-control stream cap.
- `--max-total-streams` bounds all public streams across controls in one process (default 4096, range 1..1000000); a stream beyond the limit is closed before OPEN.
- `--max-stream-bytes` bounds cumulative bytes in both directions for one stream (default 0, unlimited); exceeding it resets that stream only. UDP associations count both directions the same way.
- Public TLS can require a client certificate with `--public-tls-client-ca`; the CA is used to verify the public client identity. It requires `--public-tls-cert` and `--public-tls-key`.
- `--udp-idle-secs` controls UDP association idle expiry (default 60, range 1..86400).
- `--udp-queue` sets the UDP receive queue (default 1024, range 16..65536).
- `--udp-rate-pps` sets a per-association bidirectional packet rate (default 0, unlimited); excess datagrams are dropped and counted.
- `--udp-listen` enables public UDP relay and currently requires `--max-controls 1`; the client supplies a fixed `--udp-target`, or `--udp-socks5` for multi-target SOCKS5 UDP datagrams. The two client modes are mutually exclusive. The SOCKS5 mode parses RSV/FRAG/ATYP and rejects nonzero FRAG; replies are wrapped with the source address. Each public source address is an association with a 60-second idle timeout. UDP has no TLS; place the public port behind a trusted network or external encrypted tunnel.
- Metrics expose `relay_reverse_mux_control_limit_rejections_total`, `relay_reverse_mux_stream_limit_rejections_total`, `relay_reverse_mux_stream_byte_limit_resets_total`, and `relay_reverse_mux_udp_dropped_total`, and `relay_reverse_mux_udp_rate_limited_total`.
- The TLS server permits at most 64 simultaneous pending TLS/token authentications. TLS and authentication each have a 10-second deadline. The permit is released after READY, before serving the authenticated control. This is not a 64-established-control limit. Plaintext control authentication uses the same isolated pending-auth pattern. Each authorized control also permits at most 64 pending public TLS handshakes; public accept continues while they run. Active stream/control metrics use drop guards for cleanup.
- Regression coverage includes an 8 MiB upload followed by an 8 MiB EOF-triggered reply, slow readers with an unrelated echo stream, cancellation in both roles, partial-frame abandonment, 80 simultaneously authenticated TLS controls, and the 64-pending-authentication bound. These are loopback correctness tests, not WAN throughput or endurance certification.

## 0.112.0 UDP isolation and lifecycle

The mux client dispatches each UDP association through a bounded queue of 32
pending datagrams and an independent cancellable worker. Slow DNS, target setup
and datagram sends do not run in the shared control-frame reader. Setup and each
resolution/send operation have a five-second deadline. Overflow and rejected
replies increment the drop counter in the client process; the server's metrics
remain local to that server process.

SOCKS5-mode reply sources must match an admitted destination IP and port on the
same association. The client resolves once before checking the destination
policy and sending. Reply permissions are limited to 256 endpoints per
association and expire 60 seconds after the last admitted outgoing request.
When all entries are live, requests for additional endpoints are dropped.

FAIL, FIN and RESET immediately remove the server's UDP peer/id records and
release their admission permit. Lifecycle signals bypass the return-datagram
queue, so queue pressure cannot discard a close. The `udp-v1` framing does not
require a new acknowledgment; existing peers can still exchange datagrams.
Upgrade both peers for all R111 fixes. Client UDP destination sockets remain IPv4.

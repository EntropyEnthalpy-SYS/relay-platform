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
  --idle-timeout-secs 300

relay reverse-mux-client \
  --server PUBLIC:19010 \
  --target 127.0.0.1:8080 \
  --token-file /etc/relay/reverse.token
```

## 协议与边界

- 控制连接首行：`REVERSE <token>`；成功 `READY`，失败 `DENY`。
- 每次公网连接：服务器发 `OPEN`；客户端拨号目标，成功 `OK`，失败 `FAIL <error>`；随后原始 TCP 双向桥接。
- 控制行最长 512 字节，token 1..256 字节；每条控制连接只服务一个公网连接。token 使用长度检查加逐字节异或累积比较，避免提前返回的明显时序差异。
- 客户端 `--sessions 1..64` 启动多个独立控制会话，服务端为每个已认证控制连接派生会话任务，因此可并发服务多个公网连接；并发度受会话数限制，不是单连接多路复用。
- 客户端在会话结束/失败后 250ms 重连；服务器持续接受新的已认证控制连接。
- 没有单连接 mux、流量计量、ACL、TLS、重放保护或流量填充；控制/公网端口应置于受信网络或外部 TLS 隧道后。
- 多路复用握手：`REVERSE-MUX <token>`；token 同样使用常量时间比较；随后 9 字节帧头（kind、u32 id、u32 长度）+ 负载，kind 为 `OPEN/OK/FAIL/DATA/FIN/RESET`；帧负载上限 64 KiB。
- 服务端为每个公网连接分配 id 并发 `OPEN`，客户端拨号目标后回 `OK`，再按 id 双向转发；一条控制连接可并发承载多个公网连接。
- 服务端每条控制连接默认最多 256 个并发公网流，`--max-streams 1..1024` 可调；超过上限的新公网连接立即关闭，不分配 id。
- 公网流默认 300 秒无数据即被关闭并发送 `RESET`；`--idle-timeout-secs 1..86400` 可调。
- 客户端 `reverse-mux-client` 在控制连接断开后 250ms 重连；不提供按连接计量、ACL、TLS、重放保护或流量填充。
- 测试覆盖错误 token、单控制连接上两个并发公网连接、双目标回显、流上限校验和 idle 超时校验；旧测试覆盖顺序连接和 session pool。未做真实公网、NAT、长时或高并发验收。

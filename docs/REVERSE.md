# 单会话反向 TCP 隧道

0.53.0 增加最小反向 TCP 隧道，0.57.0 增加会话池并发。每条已认证控制连接一次承载一个公网 TCP 连接；客户端可用 `--sessions N` 并发多条控制连接，从而并发服务 N 个公网连接。它不是单连接多路复用反向隧道，也不是 WireGuard。

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

## 协议与边界

- 控制连接首行：`REVERSE <token>`；成功 `READY`，失败 `DENY`。
- 每次公网连接：服务器发 `OPEN`；客户端拨号目标，成功 `OK`，失败 `FAIL <error>`；随后原始 TCP 双向桥接。
- 控制行最长 512 字节，token 1..256 字节；每条控制连接只服务一个公网连接。
- 客户端 `--sessions 1..64` 启动多个独立控制会话，服务端为每个已认证控制连接派生会话任务，因此可并发服务多个公网连接；并发度受会话数限制，不是单连接多路复用。
- 客户端在会话结束/失败后 250ms 重连；服务器持续接受新的已认证控制连接。
- 没有单连接 mux、流量计量、ACL、TLS、重放保护或流量填充；控制/公网端口应置于受信网络或外部 TLS 隧道后。
- 测试覆盖错误的 token、两个顺序公网连接、两个并发公网连接（session pool）、目标回显和会话重连；未做真实公网、NAT、长时或高并发验收。

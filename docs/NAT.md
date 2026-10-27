# NAT 端口映射

0.42.0 增加 NAT-PMP（RFC 6886）UDP 端口映射客户端，作为模块 16 的第一个可执行能力。它不是 NAT 穿透服务器、反向隧道或 WireGuard。

## CLI

```text
relay nat-map --gateway 192.168.1.1 \
  --internal-port 9000 --external-port 40000 --lifetime-secs 3600
relay nat-map --gateway 192.168.1.1:5351 --internal-port 9000 --delete
```

- Gateway 接受 `IP` 或 `IP:PORT`；省略端口用 5351；只支持 IPv4。
- 请求/响应使用 NAT-PMP 12/16 字节 UDP 报文：版本 0、UDP map opcode 1、内部端口、建议外部端口、生命周期。
- 成功返回 `gateway/internal_port/external_port/lifetime_secs/epoch` JSON；网关拒绝、超时、版本/长度错误明确失败。
- `--external-port 0` 表示由网关分配；`--delete` 发送生命周期 0。
- 生命周期上限 7 天；内部端口不能为 0。

## 验证与限制

- 集成测试用本机假 NAT-PMP 网关验证请求字段、成功映射、epoch/外部端口解析、删除请求和拒绝响应。
- 未实现 PCP、UPnP IGD、NAT-PMP 续租/重试、IPv6、映射状态持久化、反向隧道、WireGuard、真实家用路由器验收；模块 16 仍为部分实现。
- 该命令只管理一个映射，不改变 Relay 规则或监听；需要网关实际支持 NAT-PMP。
